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
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	apiHost              = "https://master.hostname:8443"
	apiRoot              = apiHost + "/api/v1"
	wgName               = "wg66"
	sndHeartbeatInterval = 20
	spdHeartbeatInterval = 30
)

type messageType int

const (
	Hello messageType = iota
	Ping
	Pong
	Error
	Bye

	PeersRequest
	PodsRequest
	PodsList

	// SPD
	spdCreate
	spdShutdown
)

type eventType int

const (
	// Update to peers in secret
	SecretsUpdate eventType = iota

	// Called on boot, the secret is read and peers can be contacted
	SecretsInit
)

type spdMessage struct {
	Type messageType
}

// List of error types used in daemons
type errorType int

const (
	peerDoesNotExist errorType = iota
	tokenMultipleProjects
	tokenNoProject
	secretInitError

	namespaceError
)

type secshiftError struct {
	message string
	code    errorType
}

func (e *secshiftError) Error() string {
	return e.message
}

func raise(message string, code errorType) error {
	return &secshiftError{
		message: message,
		code:    code,
	}
}

type dnsMappingMap map[string][]string

func apiRequest(token string, endpoint string) (resp *http.Response, err error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", apiRoot+endpoint, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer "+token)

	return client.Do(req)
}

func getLocalIP(localInterface string) *net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("Error in request to net.Interfaces:", err)
	}

	var ip net.IP
	for _, iface := range ifaces {
		if iface.Name != localInterface {
			// Skip till own interface is found
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			log.Fatal("Error during listing addresses:", err)
		}

		for _, addr := range addrs {
			var temp net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				temp = v.IP
			case *net.IPAddr:
				temp = v.IP
			}

			if temp.To4() != nil {
				ip = temp
				break
			}
		}
		break
	}
	return &ip
}

func hashString(input string) string {
	s := sha256.Sum256([]byte(input))
	return hex.EncodeToString(s[:])
}

func hashBytes(input []byte) string {
	s := sha256.Sum256(input)
	return hex.EncodeToString(s[:])
}
