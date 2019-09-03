// SecShift - traffic security for OpenShift
// Copyright (C) 2019 Dominik Pataky <mail@dpataky.eu>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package daemons

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	opv1 "github.com/openshift/api/project/v1"
	v1 "k8s.io/api/core/v1"
	v1m "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *snd) verifyToken() error {
	req, err := http.NewRequest("GET", apiHost+"/oapi/v1/projects", nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+s.token)

	resp, err := s.apiHTTPClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		s.logger.Fatal(resp)
	}

	var list opv1.ProjectList
	err = json.NewDecoder(resp.Body).Decode(&list)
	if err != nil {
		return err
	}

	projects := list.Items

	if len(projects) > 1 {
		return raise("Token has more than one project", tokenMultipleProjects)
	}

	if len(projects) < 1 {
		return raise("Token has no project", tokenNoProject)
	}

	s.project = projects[0].Name

	s.logger.Infof("Project name identified: %s", s.project)

	return nil
}

func (s *snd) listenPodEvents() {
	endpoint := fmt.Sprintf(endpointPods, s.project)
	s.logger.Debugf("Started listener for endpoint %s", endpoint)

	// Create HTTP client and outgoing request with token
	req, err := http.NewRequest("GET", apiRoot+endpoint, nil)
	if err != nil {
		s.logger.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer "+s.token)

	// Execute the request and read responses line by line
	resp, err := s.apiHTTPClient.Do(req)
	if err != nil {
		s.logger.Fatal(err)
	}
	scanner := bufio.NewScanner(resp.Body)
	defer resp.Body.Close()

	for scanner.Scan() {
		buf := scanner.Bytes()

		var event v1m.WatchEvent
		err = json.Unmarshal(buf, &event)
		if err != nil {
			s.logger.Fatal(err)
		}

		var pod v1.Pod
		err = json.Unmarshal(event.Object.Raw, &pod)
		if err != nil {
			s.logger.Error(err)
			s.getAllPods()
			continue
		}

		name := pod.Name

		if strings.HasSuffix(name, "-build") || strings.HasSuffix(name, "-deploy") {
			// Ignore temporary Pods
			continue
		}

		if event.Type == "ADDED" || event.Type == "MODIFIED" {
			if event.Type == "ADDED" {
				s.logger.Debugf("Adding Pod %s to list of known Pods (now %d)", name, len(s.pods))
			} else {
				s.logger.Debugf("Updating existing Pod %s", name)
			}
		} else if event.Type == "DELETED" {
			s.logger.Debugf("Deleting Pod %s (now %d)", name, len(s.pods))
		} else {
			s.logger.Debugf("Unknown event type: %s", event.Type)
		}

		s.getAllPods()
	}
}

func (s *snd) listenServicesEvents() {
	endpoint := fmt.Sprintf(endpointServices, s.project)
	s.logger.Debugf("Started listener for endpoint %s", endpoint)

	// Create HTTP client and outgoing request with token
	req, err := http.NewRequest("GET", apiRoot+endpoint, nil)
	if err != nil {
		s.logger.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer "+s.token)

	// Execute the request and read responses line by line
	resp, err := s.apiHTTPClient.Do(req)
	if err != nil {
		s.logger.Fatal(err)
	}
	scanner := bufio.NewScanner(resp.Body)
	defer resp.Body.Close()

	for scanner.Scan() {
		buf := scanner.Bytes()

		var event v1m.WatchEvent
		err = json.Unmarshal(buf, &event)
		if err != nil {
			s.logger.Fatal(err)
		}
		var service v1.Service
		err := json.Unmarshal(event.Object.Raw, &service)
		if err != nil {
			s.logger.Fatal(err)
		}

		name := service.Name

		if event.Type == "ADDED" || event.Type == "MODIFIED" {
			s.logger.Debugf("Adding/modifying Service %s (now %d)", name, len(s.services))
		} else if event.Type == "DELETED" {
			s.logger.Debugf("Deleting Service %s (now %d)", name, len(s.services))
		} else {
			s.logger.Debugf("Unknown event type: %s", event.Type)
		}

		// Run Service->Pod mapping update after each new event
		s.getAllServices()
	}
}

// Explicitly request the full list of Pods from a Project.
func (s *snd) getAllPods() {
	s.logger.Infof("Getting all Pods in Project %s", s.project)

	req, err := http.NewRequest("GET", apiRoot+"/namespaces/"+s.project+"/pods", nil)
	if err != nil {
		s.logger.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer "+s.token)

	resp, err := s.apiHTTPClient.Do(req)
	if err != nil {
		s.logger.Fatal(err)
	}

	if resp.StatusCode != 200 {
		s.logger.Fatal(resp)
	}

	var list v1.PodList
	err = json.NewDecoder(resp.Body).Decode(&list)
	if err != nil {
		s.logger.Fatal(err)
	}

	// First, store the current list of pods
	stillExists := make(map[string]bool)
	for name, _ := range s.pods {
		stillExists[name] = false
	}

	for _, pod := range list.Items {
		// Skip pods which are not running
		if pod.Status.Phase != v1.PodRunning {
			continue
		}

		s.logger.Debugf("Pod %s with IP %s on host %s", pod.Name, pod.Status.PodIP, pod.Status.HostIP)
		if _, ok := s.pods[pod.Name]; !ok {
			s.logger.Warnf("Pod %s was not in list of pods, adding", pod.Name)
			s.pods[pod.Name] = pod

			// Start an SPD daemon for this pod and add it to the localPods list
			if pod.Status.HostIP == getLocalIP(s.localInterface).String() {
				s.logger.Infof("Pod %s is a local pod", pod.Name)
				s.createSPD(pod.Name)
			}
		} else {
			stillExists[pod.Name] = true
		}
	}

	for name, exists := range stillExists {
		if !exists {
			s.logger.Warnf("Pod %s was in list of pods, but does not exist anymore, deleting!", name)
			delete(s.pods, name)

			if _, ok := s.localPods[name]; ok {
				s.logger.Warnf("SPD for pod %s exists, shutting down and deleting.", name)
				s.shutdownSPD(name)
			}
		}
	}

	s.matchServicesPods()
}

func (s *snd) getAllServices() {
	s.logger.Infof("Getting all Services in Project %s", s.project)

	req, err := http.NewRequest("GET", apiRoot+"/namespaces/"+s.project+"/services", nil)
	if err != nil {
		s.logger.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer "+s.token)

	resp, err := s.apiHTTPClient.Do(req)
	if err != nil {
		s.logger.Fatal(err)
	}

	var list v1.ServiceList
	err = json.NewDecoder(resp.Body).Decode(&list)
	if err != nil {
		s.logger.Fatal(err)
	}

	// First, store the current list of pods
	stillExists := make(map[string]bool)
	for name, _ := range s.services {
		stillExists[name] = false
	}

	for _, service := range list.Items {
		s.logger.Debugf("Service %s with IP %s ", service.Name, service.Spec.ClusterIP)
		if _, ok := s.services[service.Name]; !ok {
			s.logger.Warnf("Service %s was not in list of services, adding", service.Name)
			s.services[service.Name] = service
		} else {
			stillExists[service.Name] = true
		}
	}

	for name, exists := range stillExists {
		if !exists {
			s.logger.Warnf("Service %s was in list of pods, but does not exist anymore, deleting!", name)
			delete(s.services, name)
		}
	}

	s.matchServicesPods()
}

// Matches Services to a list of Pods based on selectors and labels
func (s *snd) matchServicesPods() {
	s.logger.Info("Matching Services to Pods")

	// Map for DNS proxy
	dnsMapper := make(dnsMappingMap)

	// First iterate over all Services
	for svcName, svcObj := range s.services {
		var matches []string
		var dnsTargets []string

		// Then iterate over all Pods and match them
	Pods:
		for podName, podObj := range s.pods {
			for k, v := range svcObj.Spec.Selector {
				val, ok := podObj.Labels[k]
				if !ok {
					continue Pods
				}
				if v == val {
					// TODO: check, if multiple selectors/labels must match,
					// before append is called
					matches = append(matches, podName)
					dnsTargets = append(dnsTargets, podObj.Status.PodIP)
					continue Pods
				}
			}
		}
		s.s2p[svcName] = matches
		dnsMapper[svcObj.Spec.ClusterIP] = dnsTargets
		s.newDNSMappingQueue <- dnsMapper
	}

	s.logger.Debugf("Current S2P mapping: %v", s.s2p)
}
