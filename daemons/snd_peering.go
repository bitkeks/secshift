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
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

type message interface{}

type sndMessage struct {
	SNDID string      `json:"sndid"`
	Type  messageType `json:"type"`
}

type sndMessagePods struct {
	sndMessage
	Pods map[string]existingPod `json:"pods"`
}

func (s *snd) createSNDMessage(t messageType) *sndMessage {
	return &sndMessage{SNDID: s.id, Type: t}
}

// Run a TCP server with an endpoint for new peers.
// One SND acts as the server and one as the client.
// As soon as the Hello handshake is completed, both add the peer to their list of
// peers and pass the connection to handlePeerConn, which does not differentiate
// between server or client.
func (s *snd) startPeerInterface(wg *sync.WaitGroup) {
	var ln net.Listener
	var err error
	for port := 5001; port <= 5010; port++ {
		bindingTo := fmt.Sprintf("%s:%d", getLocalIP("wg0"), port)
		s.logger.Debugf("Trying to bind to %s", bindingTo)
		ln, err = net.Listen("tcp4", bindingTo)
		if err != nil {
			s.logger.Warn(err)
		} else {
			s.localPort = port
			break
		}
	}

	if ln == nil {
		s.logger.Fatal("Peer interface could not be started")
	}

	s.logger.Infof("Successfully started peer interface at %s", ln.Addr())
	defer ln.Close()
	wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.logger.Fatal(err)
		}

		s.logger.Debugf("New peer connection from %s", conn.RemoteAddr())

		var incoming sndMessage
		err = json.NewDecoder(conn).Decode(&incoming)
		if err != nil {
			s.logger.Warnf("json decode failed: %s", err)
			conn.Close()
			return
		}

		// Don't act on new connections which are not starting with a hello message
		if incoming.Type != Hello {
			s.logger.Debug("First message was not a Hello message")
			errormsg := s.createSNDMessage(Error)

			buf, err := json.Marshal(errormsg)
			if err != nil {
				s.logger.Fatal(err)
			}

			_, err = conn.Write(buf)
			if err != nil {
				s.logger.Fatal(err)
			}

			err = conn.Close()
			if err != nil {
				s.logger.Fatal(err)
			}
			return
		}

		peerID := incoming.SNDID

		hellomsg := s.createSNDMessage(Hello)
		buf, err := json.Marshal(hellomsg)
		if err != nil {
			s.logger.Fatalf("Error marshalling JSON in server Hello reply: %s", err)
		}
		_, err = conn.Write(buf)
		if err != nil {
			s.logger.Fatal(err)
		}

		s.logger.Infof("Handshake with %s completed", conn.RemoteAddr())

		s.peers.peers[peerID] = &sndPeer{
			conn.(*net.TCPConn),
			make(chan message),
		}

		// Create knownPods entry for this new peer
		s.knownPods[peerID] = make(map[string]existingPod)

		s.logger.Debugf("Starting goroutine handlePeerConn for %s", peerID)
		go s.handlePeerConn(peerID)
	}
}

func (s *snd) sendMessageToPeer(peerID string, msg *sndMessage) error {
	var peer *sndPeer
	if p, ok := s.peers.peers[peerID]; !ok {
		s.logger.Warnf("Peer %s has no active connection!", peerID)
		return raise("Peer does not exist", peerDoesNotExist)
	} else {
		peer = p
	}

	peer.outgoingQueue <- *msg
	return nil
}

func (s *snd) debugPeers() {
	for k, v := range s.peers.peers {
		s.logger.Debugf("Peer %s with conn from %s to %s", k, v.conn.LocalAddr(), v.conn.RemoteAddr())
	}
}

// Established peer sessions with successful handshake
func (s *snd) handlePeerConn(peerID string) {
	s.logger.Infof("Called handlePeerConn with ID %s", peerID)

	var peer *sndPeer
	if p, ok := s.peers.peers[peerID]; !ok {
		s.logger.Warnf("Peer %s not in list of peers!", peerID)
		return
	} else {
		peer = p
	}
	conn := peer.conn

	// Start outgoing channel
	go func(peer *sndPeer) {
		for msg := range peer.outgoingQueue {
			buf, err := json.Marshal(msg)
			if err != nil {
				s.logger.Fatalf("JSON marshalling failed in outgoingQueue: %s")
			}

			_, err = conn.Write(buf)
			if err != nil {
				s.logger.Fatal(err)
			}
		}

		s.logger.Debugf("Channel outgoingQueue for peer %s was closed, returning from writing goroutine", peerID)
	}(peer)

	s.logger.Debug("Announcing my Pods to all peers..")
	s.announcePods()

	// Start incoming listener
	for {
		buf := make([]byte, 4096)
		_, err := conn.Read(buf)

		if err != nil {
			// Connection closed
			s.logger.Errorf("Socket read error: %s", err)

			s.debugPeers()

			if err.Error() == "EOF" {
				s.logger.Infof("Peer %s will be removed due to closed connection.", peerID)
			} else {
				s.logger.Infof("Peer %s will be removed because of unknown error", peerID)
			}

			// Close connection from reading end
			conn.Close()

			// Close the chan for writing
			s.logger.Debugf("Closing outgoingQueue for %s", peerID)
			close(s.peers.peers[peerID].outgoingQueue)

			delete(s.peers.peers, peerID)
			return
		}

		var msg sndMessage
		err = json.NewDecoder(bytes.NewBuffer(buf)).Decode(&msg)
		if err != nil {
			s.logger.Fatal(err)
		}

		switch msg.Type {
		case Hello:
			s.logger.Debugf("Received another Hello from %s", peerID)

		case PeersRequest:
			s.logger.Debugf("Received PeersRequest from %s", peerID)

		case PodsRequest:
			s.logger.Debugf("Received PodsRequest from %s", peerID)

		case PodsList:
			s.logger.Debugf("Received PodsList from %s", peerID)

			var podsMsg sndMessagePods
			err = json.NewDecoder(bytes.NewBuffer(buf)).Decode(&podsMsg)
			if err != nil {
				s.logger.Fatal(err)
			}

			// Reset the peer's Pods list
			s.knownPods[peerID] = make(map[string]existingPod)
			for name, pod := range podsMsg.Pods {
				s.knownPods[peerID][name] = pod
			}

			// Set new peers for all known Pods
			for podName, daemon := range s.localPods {
				var remotePods []existingPod

				// peer id / ( podname / existingPod )
				for _, pods := range s.knownPods {
					// podname / existingPod
					for name, ep := range pods {
						if name == podName {
							// Don't configure SPD's own Pod as peer in Pod
							continue
						}
						remotePods = append(remotePods, ep)
					}
				}

				daemon.setPeers(remotePods)
			}

			s.logger.Debugf("Known pods: %+v", s.knownPods)

		case Ping:
			s.logger.Debugf("Received Ping from %s", peerID)
			peer.outgoingQueue <- s.createSNDMessage(Pong)

		case Pong:
			s.logger.Debugf("Received Pong from %s", peerID)

		case Bye:
			s.logger.Infof("Peer %s said Bye", msg.SNDID)

			pong := s.createSNDMessage(Bye)
			err = s.sendMessageToPeer(msg.SNDID, pong)
			if err != nil {
				s.logger.Fatal(err)
			}
			conn.Close()
			delete(s.peers.peers, msg.SNDID)

		default:
			s.logger.Warnf("Unknown messageType %s", msg.Type)
		}
	}
}

// Regularly ping all peers in the list of peers to check if the
// session is still open and working
func (s *snd) meshHeartbeat() {
	c := time.Tick(sndHeartbeatInterval * time.Second)
	for _ = range c {
		s.logger.Debug("Sending heartbeats to current peers")

		s.announcePods()

		for name, peer := range s.peers.peers {
			s.logger.Infof("Heartbeat to %s (%s)", name, peer.conn.RemoteAddr())
			peer.outgoingQueue <- s.createSNDMessage(Ping)
		}
	}
}

// Gather a list of known Pods and send them to each peer
func (s *snd) announcePods() {
	msg := sndMessagePods{
		*s.createSNDMessage(PodsList),
		s.knownPods[s.id],
	}

	s.logger.Debugf("announcePods message: %+v", msg)

	for _, v := range s.peers.peers {
		v.outgoingQueue <- msg
	}
}

func (s *snd) maintainMesh() {
	for newPeers := range s.newPeersQueue {
		// Iterate over all peers fetched from the secret
		for host, port := range newPeers {
			// Skip self
			self, _ := os.Hostname()
			if host == self {
				continue
			}

			// Check if connection to host exists already
			ips, err := net.LookupIP(host)
			if err != nil {
				s.logger.Fatal(err)
			}

			idenfiedPeer := ""
			for name, peer := range s.peers.peers {
				if peer.conn.RemoteAddr().(*net.TCPAddr).IP.Equal(ips[0]) {
					idenfiedPeer = name
					break
				}
			}

			if idenfiedPeer != "" {
				// Host is already a peer
				// TODO: connection checking?

				s.logger.Debugf("Peer %s has existing connection, skipped in iteration over newPeers", idenfiedPeer)

				// There's no connection to close
				continue
			}

			// Peer does not exist yet

			if host < self {
				// Lower node IDs make establish the connection
				s.logger.Debugf("Peer %s has no existing connection, but will establish the connection, skipping", host)
				continue
			}

			// Host does not yet exist in list of peers and we are the lower node ID
			s.logger.Debugf("Peer %s is not yet established, connecting", host)

			// Build TCPAddr
			tcpAddr, err := net.ResolveTCPAddr("tcp", host+":"+strconv.Itoa(port))
			if err != nil {
				s.logger.Fatalf("Building tcpAddr failed: %s", err)
			}

			// Establish connection
			conn, err := net.DialTCP("tcp", nil, tcpAddr)
			if err != nil {
				s.logger.Warnf("Connection to %s failed: %s", tcpAddr, err)
				continue
			}

			hellomsg := s.createSNDMessage(Hello)
			buf, _ := json.Marshal(hellomsg)
			_, err = conn.Write(buf)
			if err != nil {
				s.logger.Fatalf("Error sending Hello from maintainMesh: %s", err)
			}

			buf = make([]byte, 4096)
			_, err = conn.Read(buf)
			if err != nil {
				s.logger.Fatalf("Error reading response in maintainMesh: %s", err)
			}

			var reply sndMessage
			err = json.NewDecoder(bytes.NewBuffer(buf)).Decode(&reply)
			if err != nil {
				s.logger.Fatal(err)
			}

			peerID := reply.SNDID

			s.logger.Debugf("Server %s replied with Hello handshake. Adding peer to list of peers", peerID)
			s.peers.peers[peerID] = &sndPeer{
				conn,
				make(chan message),
			}

			// Create knownPods entry for this new peer
			s.knownPods[peerID] = make(map[string]existingPod)

			// Connection stays open, picked up by handlePeerConn
			go s.handlePeerConn(reply.SNDID)
		}
	}

}
