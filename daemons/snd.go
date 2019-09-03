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
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"

	v1 "k8s.io/api/core/v1"

	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

const (
	endpointServices = "/watch/namespaces/%s/services?watch=true"
	endpointPods     = "/namespaces/%s/pods?watch=true"

	eventPod     = 1
	eventService = 2
)

type snd struct {
	id             string
	token          string
	localInterface string
	localPort      int
	project        string
	sharedSecret   string

	pods      map[string]v1.Pod
	services  map[string]v1.Service
	s2p       map[string][]string
	localPods map[string]*spd

	// { sndid: { podName: Pod } }
	knownPods map[string]map[string]existingPod

	newPeersQueue      chan map[string]int
	newDNSMappingQueue chan dnsMappingMap
	newSPDQueue        chan bool

	// Actual peers with established connections
	peers *sndPeers

	dclient       *client.Client
	apiHTTPClient *http.Client
	logger        *logrus.Logger
}

// SNDs peer with each other
type sndPeer struct {
	// Established TCP connection
	conn *net.TCPConn

	// Channel for messages which are to be sent to the peer
	// Handled in a goroutine
	outgoingQueue chan message
}

// Struct holding the SND peers
// Held a lock in earlier versions, that's why it is a struct
type sndPeers struct {
	peers map[string]*sndPeer
}

// Create an SND daemon instance
func CreateSND(token, localInterface string) *snd {
	return &snd{
		token:          token,
		localInterface: localInterface,
	}
}

func (s *snd) createSPD(podName string) {
	p := s.findPodContainer(podName)
	cpid := s.getPodPid(p)
	commandChan := make(chan spdMessage)
	updatesChan := make(chan bool)
	dnsChan := make(chan dnsMappingMap)
	newSPD := createSPD(podName, cpid, commandChan, updatesChan, dnsChan)

	// Lock the new SPD to ensure a complete setup before query() can be run
	newSPD.setup.Add(1)

	go func(updatesChan chan bool) {
		for _ = range updatesChan {
			s.logger.Debugf("Updates channel triggered by SPD %s", newSPD.id)
			s.knownPods[s.id][podName] = *newSPD.query()
			s.announcePods()
		}
	}(updatesChan)

	go newSPD.start()

	s.localPods[podName] = newSPD
	s.knownPods[s.id][podName] = *newSPD.query()
}

func (s *snd) updateDNS() {
	for m := range s.newDNSMappingQueue {
		for _, pd := range s.localPods {
			pd.dnsChan <- m
		}
	}
}

func (s *snd) shutdownSPD(podName string) {
	spdInstance := s.localPods[podName]
	spdInstance.shutdown()
	close(spdInstance.commandChan)
	delete(s.localPods, podName)
}

// Start the daemon
func (s *snd) Start() {
	// Set up logging
	s.logger = logrus.New()
	s.logger.Level = logrus.DebugLevel
	s.logger.Out = os.Stdout
	s.logger.SetFormatter(&logrus.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})

	dclient, err := client.NewEnvClient()
	if err != nil {
		s.logger.Fatal(err)
	}
	s.dclient = dclient
	s.logger.Debugf("Initialised Docker client")

	s.apiHTTPClient = &http.Client{}

	s.verifyToken()

	// Create a unique ID for this daemon.
	// Used by other daemons to identify this daemon.
	h, _ := os.Hostname()
	s.id = strings.Split(h, ".")[0] + ":snd:" + s.project

	s.logger.Debugf("Running as SND with ID %s", s.id)

	s.sharedSecret = hashString(s.token + s.project)

	// Start the listener interface and wait for it to be initialized
	var wg sync.WaitGroup
	wg.Add(1)
	go s.startPeerInterface(&wg)
	wg.Wait()

	s.pods = make(map[string]v1.Pod)
	s.services = make(map[string]v1.Service)
	s.s2p = make(map[string][]string)

	s.localPods = make(map[string]*spd)
	s.knownPods = make(map[string]map[string]existingPod)

	// Create own knownPods entry
	s.knownPods[s.id] = make(map[string]existingPod)

	s.peers = new(sndPeers)
	s.peers.peers = make(map[string]*sndPeer)

	s.newPeersQueue = make(chan map[string]int, 10)
	s.newDNSMappingQueue = make(chan dnsMappingMap, 10)

	go s.listenPodEvents()
	go s.listenServicesEvents()

	go s.updateDNS()

	// Handle secret update with the allocated port
	_, err = s.verifySecret()
	if err != nil {
		s.logger.Fatalf("Error in verifySecret: %s", err)
	}
	go s.watchSecret()

	// Maintain the mesh, making connections on Secret update
	go s.maintainMesh()

	// Regularly send heartbeats
	go s.meshHeartbeat()

	// Interrupt handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	wg.Add(1)

	// Run interrupt handler (ctrl-c)
	go func() {
		for _ = range c {
			s.removeSecretEntry()
			wg.Done()
			return
		}
	}()

	wg.Wait()
	s.logger.Info("Shutting down")
}
