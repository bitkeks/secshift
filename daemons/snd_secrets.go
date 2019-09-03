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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	v1 "k8s.io/api/core/v1"
	v1m "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

func encodeBase64(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

func decodeBase64(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(input)
}

func (s *snd) doPatch(opList *[]patchOp) (*v1.Secret, error) {
	payload, err := json.Marshal(opList)
	if err != nil {
		s.logger.Error(err)
	}

	// Issue request against the secrets API
	req, err := http.NewRequest("PATCH", apiRoot+"/namespaces/"+s.project+"/secrets/secshift", bytes.NewBuffer(payload))
	req.Header.Add("Authorization", "Bearer "+s.token)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json-patch+json")

	resp, err := s.apiHTTPClient.Do(req)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	// Debug error responses
	if resp.StatusCode != 200 {
		s.logger.Debug(resp)
		buf, _ := ioutil.ReadAll(resp.Body)
		s.logger.Debugf("Response: %s", buf)
		return nil, raise(string(buf), secretInitError)
	}

	var secret v1.Secret
	err = json.NewDecoder(resp.Body).Decode(&secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

// Initialize the secshift secret, if no "data" key exist.
func (s *snd) initializeSecret() (*v1.Secret, error) {
	host, _ := os.Hostname()
	opList := []patchOp{}
	newOp := patchOp{
		Op:    "add",
		Path:  "/data",
		Value: json.RawMessage(`{"` + host + `": "` + encodeBase64([]byte(strconv.Itoa(s.localPort))) + `"}`),
	}

	opList = append(opList, newOp)
	return s.doPatch(&opList)
}

func (s *snd) createSecretEntry() (*v1.Secret, error) {
	s.logger.Debug("Creating new entry in Secret")
	host, _ := os.Hostname()
	opList := []patchOp{}
	newOp := patchOp{
		Op:    "add",
		Path:  "/data/" + host,
		Value: json.RawMessage(`"` + encodeBase64([]byte(strconv.Itoa(s.localPort))) + `"`),
	}

	opList = append(opList, newOp)
	return s.doPatch(&opList)
}

// Update an existing entry for this host in the secret
func (s *snd) updateSecretEntry() (*v1.Secret, error) {
	s.logger.Debug("Updating entry in Secret")
	host, _ := os.Hostname()
	opList := []patchOp{}
	newOp := patchOp{
		Op:    "replace",
		Path:  "/data/" + host,
		Value: json.RawMessage(`"` + encodeBase64([]byte(strconv.Itoa(s.localPort))) + `"`),
	}

	opList = append(opList, newOp)
	return s.doPatch(&opList)
}

// Delete an existing entry for this host in the secret
func (s *snd) removeSecretEntry() (*v1.Secret, error) {
	s.logger.Debug("Removing entry in Secret")
	host, _ := os.Hostname()
	opList := []patchOp{}
	newOp := patchOp{
		Op:   "remove",
		Path: "/data/" + host,
	}

	opList = append(opList, newOp)
	return s.doPatch(&opList)
}

// Create listedPeers map
func (s *snd) newListedPeers(secret *v1.Secret) error {
	listedPeers := make(map[string]int)
	for host, v := range secret.Data {
		// value is already a decoded []byte (from base64)
		port, err := strconv.Atoi(string(v))
		if err != nil {
			return err
		}
		listedPeers[host] = port
	}
	s.newPeersQueue <- listedPeers
	s.logger.Debugf("New listedPeers: %v", listedPeers)
	return nil
}

// Watch the SecShift secret
func (s *snd) watchSecret() {
	// Restart the request if the endpoint was disconnected
	var connectionTries = 0
	for {
		if connectionTries > 5 {
			s.logger.Fatal("Secret endpoint did not respond in 5 tries")
		}

		// Watch for updates
		req, err := http.NewRequest("GET", apiRoot+"/watch/namespaces/"+s.project+"/secrets/secshift?watch=1", nil)
		if err != nil {
			s.logger.Fatal(err)
		}
		req.Header.Add("Authorization", "Bearer "+s.token)

		// Execute the request and read responses line by line
		resp, err := s.apiHTTPClient.Do(req)
		if err != nil {
			s.logger.Error(err)
			connectionTries++
			continue
		}

		connectionTries = 0

		scanner := bufio.NewScanner(resp.Body)
		defer resp.Body.Close()

		s.logger.Info("Started listener on Secret")

		for scanner.Scan() {
			buf := scanner.Bytes()

			var event v1m.WatchEvent
			err = json.Unmarshal(buf, &event)
			if err != nil {
				s.logger.Fatal(err)
			}

			var secret v1.Secret
			err = json.Unmarshal(event.Object.Raw, &secret)
			if err != nil {
				s.logger.Error(err)
				continue
			}

			s.logger.Debugf("%s secret: %s", event.Type, secret.Data)
			err := s.newListedPeers(&secret)
			if err != nil {
				s.logger.Fatal(err)
			}
		}

		s.logger.Debug("Secrets endpoint scanner finished, restarting listener.")
	}
}

// Get the current state of the SecShift secret in this project.
// If the secret has no data, it is initialized.
func (s *snd) verifySecret() (*v1.Secret, error) {
	req, err := http.NewRequest("GET", apiRoot+"/namespaces/"+s.project+"/secrets/secshift", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+s.token)

	resp, err := s.apiHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	var secret v1.Secret
	err = json.NewDecoder(resp.Body).Decode(&secret)
	if err != nil {
		return nil, err
	}

	host, _ := os.Hostname()

	// If secret is empty, create "data" key with this node's data
	if len(secret.Data) == 0 {
		s.logger.Debug("Secret data is empty, initializing")
		sec, err := s.initializeSecret()
		if err != nil {
			s.logger.Fatal(err)
		}
		secret = *sec
	} else if data, ok := secret.Data[host]; !ok {
		s.logger.Info("Data for own host is not yet in secret")
		// Hostname key does NOT exist yet
		sec, err := s.createSecretEntry()
		if err != nil {
			return nil, err
		}
		secret = *sec
	} else {
		s.logger.Debugf("Existing data in secret: %s", data)
		// Hostname key DOES exist already

		// Situation: there's no MODIFIED if the value does not change in the update PATCH
		// Fix: remove and create
		_, err := s.removeSecretEntry()
		if err != nil {
			return nil, err
		}

		sec, err := s.createSecretEntry()
		if err != nil {
			return nil, err
		}
		secret = *sec
	}

	err = s.newListedPeers(&secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}
