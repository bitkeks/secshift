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

// Based on Tencrypt implementation

import (
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netns"
)

var (
	MTU = 1300
)

// Proxy DNS to inspect internal/external vIPs and to keep track of route whitelistings
func (s *spd) proxyDNS() {
	// Fetch the host's IP address before switching namespaces
	var upstreamAddr net.UDPAddr
	upstreamAddr.IP = *getLocalIP("eth0")
	upstreamAddr.Port = 53

	// Switch network namespaces to bind to container loopback interface
	nsContainer, err := netns.GetFromPid(s.containerPid)
	if err != nil {
		s.logger.Fatal(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	nsCurrent, _ := netns.Get()
	defer nsCurrent.Close()

	netns.Set(nsContainer)
	defer nsContainer.Close()

	// Switch back to the original namespace on return
	defer netns.Set(nsCurrent)

	// Map holding existing client connections to be answered after relaying the query
	var queryResponseMapper = struct {
		sync.RWMutex
		entries map[uint16]*net.UDPAddr
	}{entries: make(map[uint16]*net.UDPAddr)}

	// Create the local DNS UDP listener socket
	var listenAdd net.UDPAddr
	listenAdd.Port = 53
	listenAdd.IP = net.IPv4(127, 0, 0, 1)
	listener, err := net.ListenUDP("udp", &listenAdd)
	if err != nil {
		s.logger.Error("Something went wrong while proxying DNS: %s", err)
	}
	defer listener.Close()

	// Create one static connection to upstream DNS server
	upstreamConn, err := net.DialUDP("udp", nil, &upstreamAddr)
	if err != nil {
		s.logger.Error(err)
	}

	// Add iptables NAT rule
	ipt, err := iptables.New()
	if err != nil {
		s.logger.Errorf("Error in iptables: %s", err)
	}
	err = ipt.ClearChain("nat", "OUTPUT")
	if err != nil {
		s.logger.Errorf("Error flushing NAT OUTPUT: %s", err)
	}
	err = ipt.Append("nat", "OUTPUT", "--proto", "udp", "--out-interface", "eth0", "-m", "owner", "!", "--uid-owner", strconv.Itoa(os.Getuid()), "--destination", upstreamAddr.IP.String(), "--dport", "53", "-j", "DNAT", "--to-destination", "127.0.0.1:53")
	if err != nil {
		s.logger.Errorf("Error appending NAT iptables rule for %s: %s", upstreamAddr.IP.String(), err)
	}

	// Initialise random for target choices
	rand.Seed(time.Now().UnixNano())

	// Run the upstream connection handling async
	// Parses and evaluates answers from upstream DNS, extracting information about
	// whether a host is Project-internal or -external
	go func() {
		buffer := make([]byte, MTU)
		for {
			n, err := upstreamConn.Read(buffer[0:])
			if err != nil {
				s.logger.Error(err)
			}

			// Parse the DNS packet
			packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeDNS, gopacket.Default)
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			dns, _ := dnsLayer.(*layers.DNS)

			var answers []layers.DNSResourceRecord

			// Examine the DNS responses/answers
			for _, ans := range dns.Answers {
				if ans.Type == layers.DNSTypeA {
					hostname := string(ans.Name)
					ip := ans.IP.String()

					s.logger.Debugf("DNS answer from upstream: %s %s", hostname, ip)

					for sip, tips := range s.dnsMappings {
						if sip == ip {
							// Choose a random target IP which replaces this Service IP
							target := tips[rand.Intn(len(tips))]
							ans.IP = net.ParseIP(target)
							s.logger.Debugf("DNS answer rewritten to: %s %s", hostname, ans.IP.String())
							break
						}
					}
				}

				answers = append(answers, ans)
			}

			dns.Answers = answers

			queryResponseMapper.RLock()
			client, exists := queryResponseMapper.entries[dns.ID]
			queryResponseMapper.RUnlock()

			if !exists {
				s.logger.Error("Something went wrong with the queryResponseMapper when looking up the DNS ID")
				continue
			}

			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{}
			err = dns.SerializeTo(buf, opts)
			if err != nil {
				panic(err)
			}

			n, err = listener.WriteToUDP(buf.Bytes(), client)
			if err != nil {
				s.logger.Error(err)
			}

			queryResponseMapper.Lock()
			delete(queryResponseMapper.entries, dns.ID)
			queryResponseMapper.Unlock()
		}
	}()

	// Start the local listener service
	buffer := make([]byte, MTU)
	for {
		// Receive DNS queries from listener socket
		n, client, err := listener.ReadFromUDP(buffer[0:])
		if err != nil {
			s.logger.Error(err)
		}

		packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeDNS, gopacket.Default)
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		dns, _ := dnsLayer.(*layers.DNS)

		//~ s.logger.Debugf("Received DNS request: %+v", dns)

		queryResponseMapper.Lock()
		queryResponseMapper.entries[dns.ID] = client
		queryResponseMapper.Unlock()

		// Write client request to upstream
		n, err = upstreamConn.Write(buffer[0:n])
	}
}
