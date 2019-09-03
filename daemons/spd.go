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
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	dnl "github.com/docker/libcontainer/netlink"
	"github.com/sirupsen/logrus"
	vnl "github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	wgPort     = 6666
	wgMark     = 0x42
	tunnelMark = 0x64
)

type spd struct {
	setup *sync.WaitGroup

	id           string
	podName      string
	containerPid int
	commandChan  chan spdMessage
	updatesChan  chan bool
	dnsChan      chan dnsMappingMap

	overlayIP   net.IP
	pubkey      wgtypes.Key
	dnsMappings dnsMappingMap

	logger *logrus.Logger
}

type existingPod struct {
	PodName    string      `json:"podname"`
	Spdid      string      `json:"spdid"`
	OverlayIP  net.IP      `json:"overlayip"`
	InternalIP net.IP      `json:"internalip"`
	Pubkey     wgtypes.Key `json:"pubkey"`
}

func (s *spd) getOverlayIP() error {
	nsContainer, err := netns.GetFromPid(s.containerPid)
	if err != nil {
		return err
	}

	handler, err := vnl.NewHandleAt(nsContainer)
	if err != nil {
		return err
	}

	eth0, err := handler.LinkByName("eth0")
	if err != nil {
		return err
	}

	addrs, err := handler.AddrList(eth0, vnl.FAMILY_V4)
	if err != nil {
		return err
	}

	s.logger.Debugf("getOverlayIP addrs: %v", addrs)

	s.overlayIP = addrs[0].IP

	return nil
}

func (s *spd) configureWireguardInterface() error {
	// Lock thread to prevent switching of namespaces
	return nil
}

func (s *spd) setPeers(pods []existingPod) {
	s.modifyNamespace(pods)
}

// Execute commands in a container namespace, adding links and modifying them.
func (s *spd) modifyNamespace(peers []existingPod) (*existingPod, error) {
	nsContainer, err := netns.GetFromPid(s.containerPid)
	if err != nil {
		return nil, err
	}

	// For now, we need to switch to the namespace because vnl.Handler.LinkAdd
	// throws panic during the creation of a GenericLink

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	nsCurrent, _ := netns.Get()
	defer nsCurrent.Close()

	netns.Set(nsContainer)
	defer nsContainer.Close()

	// Switch back to the original namespace on return
	defer netns.Set(nsCurrent)

	// Get vnl.Handler in the network namespace
	handler, err := vnl.NewHandleAt(nsContainer)
	if err != nil {
		return nil, err
	}
	defer handler.Delete()

	wc, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wc.Close()

	devs, err := wc.Devices()
	if err != nil {
		return nil, err
	}

	if len(devs) == 0 {
		// Create new link with type wireguard
		err := dnl.NetworkLinkAdd(wgName, "wireguard")
		if err != nil {
			return nil, err
		}

		s.logger.Warn("No WireGuard interfaces in this namespace!")

		iface, err := net.InterfaceByName(wgName)
		if err != nil {
			return nil, err
		}

		rand.Seed(time.Now().UnixNano())
		newIP := net.IPv4(10, 66, byte(rand.Intn(230)+1), byte(rand.Intn(230)+1))
		err = dnl.NetworkLinkAddIp(iface, newIP, &net.IPNet{newIP, net.CIDRMask(16, 32)})
		if err != nil {
			return nil, err
		}
		s.logger.Infof("Set IP of new interface to %s", newIP)

		// Generate a new private key
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}

		// Create config for new wireguard interface
		config := &wgtypes.Config{
			PrivateKey:   &key,
			ListenPort:   &wgPort,
			FirewallMark: &wgMark,
			ReplacePeers: true,
			Peers:        nil,
		}

		dev, err := wc.Device(wgName)
		if err != nil {
			s.logger.Errorf("Device: %s", err)
			return nil, err
		} else if dev.Name == "" {
			s.logger.Errorf("Found device has no name, assuming namespace error during query for %s", wgName)
			return nil, raise("Namespace error", namespaceError)
		}

		// Apply the config to the interface
		err = wc.ConfigureDevice(wgName, *config)
		if err != nil {
			return nil, err
		}

		s.logger.Debug("WireGuard device configured!")
	}

	// Disable rp_filter via sysctl for both interfaces
	for _, i := range []string{"all", "wg66"} {
		err = ioutil.WriteFile("/proc/sys/net/ipv4/conf/"+i+"/rp_filter", []byte("0"), 0644)
		if err != nil {
			s.logger.Errorf("Error in sysctl: %s", err)
			return nil, err
		}
	}

	// Configure routing and MARKing

	// Configure policy for MARK 0x42
	rules, err := handler.RuleList(vnl.FAMILY_V4)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	ruleExists := false
	for _, rule := range rules {
		if rule.Table == 2 && rule.Mark == tunnelMark {
			ruleExists = true
		}
	}

	if !ruleExists {
		rule := vnl.NewRule()
		rule.Family = vnl.FAMILY_V4
		rule.Table = 2
		rule.Mark = tunnelMark
		rule.Mask = 0xfffffff

		err = handler.RuleAdd(rule)
		if err != nil {
			s.logger.Errorf("Error with new rule: %s", err)
		}
	}

	// Set wg66 up so routes can be configured
	iface, _ := net.InterfaceByName(wgName)
	dnl.NetworkLinkUp(iface)

	// Setup default route for fwmark 0x42 via the wg66 interface

	// Build the route
	tableRoute := &vnl.Route{
		Gw:    *getLocalIP(wgName),
		Table: 2,
	}

	// Query the existing routes and look if it exists
	// filtered by table only!
	routes, err := handler.RouteListFiltered(vnl.FAMILY_V4, tableRoute, vnl.RT_FILTER_TABLE)
	if err != nil {
		s.logger.Errorf("Error with routes: %s", routes)
		return nil, err
	}

	if len(routes) == 0 {
		err = handler.RouteAdd(tableRoute)
		if err != nil {
			s.logger.Errorf("Error adding route: %s", err)
		}
	} else {
		err = handler.RouteReplace(tableRoute)
		if err != nil {
			s.logger.Errorf("Error replacing route: %s", err)
		}
	}

	// Setup iptables MARK
	ipt, err := iptables.New()
	if err != nil {
		s.logger.Errorf("Error in iptables: %s", err)
	}

	// Device exists, examining
	dev, _ := wc.Device(wgName)
	ep := &existingPod{
		s.podName,
		s.id,
		s.overlayIP,
		*getLocalIP(wgName),
		dev.PublicKey,
	}
	s.logger.Debugf("%+v", ep)

	// Configure peers
	if peers != nil {
		// Flush the OUTPUT mangle table with probably existing rules
		err = ipt.ClearChain("mangle", "OUTPUT")
		if err != nil {
			s.logger.Errorf("Error flushing mangle OUTPUT: %s", err)
			return nil, err
		}

		// Create PeerConfig for each peer
		var newPeers []wgtypes.PeerConfig
		for _, peer := range peers {
			newConf := wgtypes.PeerConfig{
				PublicKey: peer.Pubkey,
				Endpoint:  &net.UDPAddr{peer.OverlayIP, wgPort, ""},
				AllowedIPs: []net.IPNet{
					net.IPNet{peer.InternalIP, net.CIDRMask(32, 32)},
					net.IPNet{peer.OverlayIP, net.CIDRMask(32, 32)},
				},
			}
			newPeers = append(newPeers, newConf)

			// Add iptables rule for packet marking
			err = ipt.Append("mangle", "OUTPUT", "--destination", peer.OverlayIP.String(), "-p", "udp", "--dport", "6666", "-j", "ACCEPT")
			if err != nil {
				s.logger.Errorf("Error appending WireGuard mangle exception iptables rule for %s: %s", peer.OverlayIP.String(), err)
				return nil, err
			}

			err = ipt.Append("mangle", "OUTPUT", "--destination", peer.OverlayIP.String(), "-j", "MARK", "--set-mark", "0x64")
			if err != nil {
				s.logger.Errorf("Error appending fwmark iptables rule for %s: %s", peer.OverlayIP.String(), err)
				return nil, err
			}
		}

		// Apply the config with the created peers
		// TODO: don't replace in whole, but only single peers, deleting if needed
		config := wgtypes.Config{
			PrivateKey:   &dev.PrivateKey,
			ListenPort:   &wgPort,
			FirewallMark: &wgMark,
			ReplacePeers: true,
			Peers:        newPeers,
		}

		//~ s.logger.Debugf("New interface config: %+v", config)

		err = wc.ConfigureDevice(wgName, config)
		if err != nil {
			s.logger.Errorf("Error in config for new peers: %s", err)
		}
	}

	return ep, nil
}

func createSPD(name string, cpid int, commandChan chan spdMessage, updatesChan chan bool, dnsChan chan dnsMappingMap) *spd {
	h, _ := os.Hostname()
	id := strings.Split(h, ".")[0] + ":spd:" + name

	return &spd{
		id:           id,
		podName:      name,
		containerPid: cpid,
		commandChan:  commandChan,
		updatesChan:  updatesChan,
		dnsChan:      dnsChan,
		setup:        &sync.WaitGroup{},
	}
}

func (s *spd) query() *existingPod {
	s.setup.Wait()
	pod, err := s.modifyNamespace(nil)
	if err != nil {
		s.logger.Fatalf("Error in query(): %s", err)
	}
	return pod
}

func (s *spd) start() {
	s.logger = logrus.New()
	s.logger.Level = logrus.DebugLevel
	s.logger.Out = os.Stdout

	s.getOverlayIP()
	s.logger.Infof("Started SPD %s in pod %s (container PID %d, IP %s)", s.id, s.podName, s.containerPid, s.overlayIP)

	_, err := s.modifyNamespace(nil)
	if err != nil {
		s.logger.Error(err)
	}

	go func() {
		for m := range s.dnsChan {
			s.dnsMappings = m
			s.logger.Debugf("New dnsMappings: %+v", s.dnsMappings)
		}
	}()

	go s.proxyDNS()

	// It's locked after creation, so the setup is running before query() is answered
	s.setup.Done()

	c := time.Tick(spdHeartbeatInterval * time.Second)
	for {
		select {
		case command := <-s.commandChan:
			s.logger.Debugf("%s received command: %v", s.id, command)
			if command.Type == spdShutdown {
				s.logger.Infof("Shutting down SPD %s", s.id)
				return
			}
		case _ = <-c:
			s.logger.Debugf("Heartbeat from SPD %s", s.id)
		}
	}
}

func (s *spd) shutdown() {
	s.logger.Info("spd.Shutdown() called")
	msg := spdMessage{
		Type: spdShutdown,
	}
	s.commandChan <- msg
}
