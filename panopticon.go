/*
 *    Wherefore main command line tool for monitoring network traffic
 *    on a IP stream basis.
 *
 *    Forked from the HoneyBadger core library for detecting TCP injection attacks
 *
 *    Copyright (C) 2015 Josh Roppo, Lytics.io, David Stainton
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package HoneyBadger

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"runtime"
	"sort"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/david415/HoneyBadger/types"
	"github.com/drewlanenga/govector"
	"github.com/google/gopacket/layers"

	"github.com/hashicorp/golang-lru"
)

const (
	NA = math.SmallestNonzeroFloat64
)

var ipv4Str string

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func init() {
	ipv4Str = GetLocalIP()
	log.Infof("IPv4 Addr: %s", ipv4Str)
}

func LRUKey(src, dst string) string {
	return fmt.Sprintf("%s->%s", src, dst)
}

//Opticon is a type ofr Sorting Pan slices
type Opticon []*Pan

func (o Opticon) Len() int {
	return len(o)
}

func (o Opticon) Swap(i, j int) {
	o[i], o[j] = o[j], o[i]
}

func (o Opticon) Less(i, j int) bool {
	return o[i].gv.Mean() < o[j].gv.Mean()
}

type OpticonError struct {
	When time.Time
	What string
}

func (oe OpticonError) Error() string {
	return fmt.Sprintf("%v: %v", oe.When, oe.What)
}

// PanRoutine initializes the PanCtl(Pan) structs and controlling channels,
//   and the PacketManifest processing goroutine.
func PanRoutine(packetManifest *types.PacketManifest, interval string, anomTest chan<- *Pan, closePan chan *PanCtl) *PanCtl {
	updateChan := make(chan *types.PacketManifest)
	stopChan := make(chan bool)
	p := NewPan(packetManifest.IP.SrcIP.String(), packetManifest.IP.DstIP.String())
	pCtl := &PanCtl{P: p, PMchan: updateChan, Stop: stopChan}

	go func() {

		tickerInterval, err := time.ParseDuration(interval)
		if err != nil {
			log.Errorf("Unable to parse string to time duration interval: %#v", err)
		}
		ticker := time.NewTicker(tickerInterval)
		breakFor := false
		breakerCount := 0

		for {
			select {
			case <-stopChan:
				breakFor = true
				log.Debugf("Stop command received for goutine listener %s", p.String())
			case <-ticker.C:
				p.updates += 1

				if p.transfered == 0 {
					breakerCount++
					if breakerCount > 60 {
						log.Debugf("Breaker count stopping goroutine listener for %s", p.String())
						closePan <- pCtl
					}
				} else {
					breakerCount = 0
				}
				// Run anomalyzer
				// Send Pan struct to AnomalyTester()
				anomTest <- p
				p.Flush()
			case pm := <-updateChan:
				dlen := len(pm.Payload)
				p.lastPM = pm
				p.AddTransfer(uint64(dlen))
			}
			if breakFor {
				log.Debugf("Stopping goroutine handling: %s", p.String())
				break
			}
		}
	}()

	return pCtl
}

func DecodeLayersInfo(p *types.PacketManifest) string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("HostIP: %s\n", ipv4Str))
	for _, typ := range p.DecodedLayers {
		switch typ {
		case layers.LayerTypeEthernet:
			buffer.WriteString(fmt.Sprintf("    Eth %v -> %v", p.Eth.SrcMAC, p.Eth.DstMAC))
			buffer.WriteString("\n")
		case layers.LayerTypeIPv4:
			buffer.WriteString(fmt.Sprintf("    IP4 %v -> %v", p.IPv4.SrcIP, p.IPv4.DstIP))
			buffer.WriteString("\n")
		case layers.LayerTypeIPv6:
			buffer.WriteString(fmt.Sprintf("    IP6 %v -> %v", p.IPv6.SrcIP, p.IPv6.DstIP))
			buffer.WriteString("\n")
		case layers.LayerTypeTCP:
			buffer.WriteString(fmt.Sprintf("    TCP %v -> %v", p.TCP.SrcPort, p.TCP.DstPort))
			buffer.WriteString("\n")
		case layers.LayerTypeUDP:
			buffer.WriteString(fmt.Sprintf("    UDP %v -> %v", p.UDP.SrcPort, p.UDP.DstPort))
			buffer.WriteString("\n")
		}
	}
	return buffer.String()
}

// Creates a map of useful Source and Destination information from the PacketManifest
//  Primarily created for Logging
func DecodeLayersMap(p *types.PacketManifest) map[string]interface{} {
	layerMap := make(map[string]interface{})

	for _, typ := range p.DecodedLayers {
		switch typ {
		case layers.LayerTypeEthernet:
			//fmt.Sprintf("    Eth %v -> %v", p.Eth.SrcMAC, p.Eth.DstMAC))
			layerMap["EthSrcMAC"] = fmt.Sprintf("%v", p.Eth.SrcMAC)
			layerMap["EthSrcMAC"] = fmt.Sprintf("%v", p.Eth.DstMAC)
		case layers.LayerTypeIPv4:
			//buffer.WriteString(fmt.Sprintf("    IP4 %v -> %v", p.IPv4.SrcIP, p.IPv4.DstIP))
			layerMap["IPv4SrcIP"] = fmt.Sprintf("%v", p.IPv4.SrcIP)
			layerMap["IPv4DstIP"] = fmt.Sprintf("%v", p.IPv4.DstIP)
		case layers.LayerTypeIPv6:
			//buffer.WriteString(fmt.Sprintf("    IP6 %v -> %v", p.IPv6.SrcIP, p.IPv6.DstIP))
			layerMap["IPv6SrcIP"] = fmt.Sprintf("%v", p.IPv6.SrcIP)
			layerMap["IPv6DstIP"] = fmt.Sprintf("%v", p.IPv6.DstIP)
		case layers.LayerTypeTCP:
			//buffer.WriteString(fmt.Sprintf("    TCP %v -> %v", p.TCP.SrcPort, p.TCP.DstPort))
			layerMap["TCPSrcPort"] = fmt.Sprintf("%v", p.TCP.SrcPort)
			layerMap["TCPDstPort"] = fmt.Sprintf("%v", p.TCP.DstPort)
		case layers.LayerTypeUDP:
			//buffer.WriteString(fmt.Sprintf("    UDP %v -> %v", p.UDP.SrcPort, p.UDP.DstPort))
			layerMap["UDPSrcPort"] = fmt.Sprintf("%v", p.UDP.SrcPort)
			layerMap["UDPDstPort"] = fmt.Sprintf("%v", p.UDP.DstPort)
		}
	}
	return layerMap
}

type PanCtl struct {
	P      *Pan
	PMchan chan *types.PacketManifest
	Stop   chan bool
}

//Pan objects watch each IP connection's traffic and total its traffic over time
type Pan struct {
	src        string
	dst        string
	opened     time.Time
	Last       time.Time
	updates    int8
	transfered uint64
	//GoVector for evaluation by Anomalyzer
	gv     *govector.Vector
	lastPM *types.PacketManifest
}

func NewPan(src, dst string) *Pan {
	g := make(govector.Vector, 30, 30)
	p := &Pan{src: src, dst: dst, opened: time.Now(), transfered: 0, gv: &g}
	//Start Goroutine to average intake via channel
	return p
}

func (p *Pan) Flush() {
	p.gv.PushFixed(float64(p.transfered))
	p.LastUpdate()
	p.ResetTransfered()
	p.updates = 0
}

func (p *Pan) String() string {
	return fmt.Sprintf("%14s -> %14s", p.src, p.dst)
}

func (p *Pan) Transfered() uint64 {
	return p.transfered
}

func (p *Pan) LastUpdate() {
	p.Last = time.Now()
}

func (p *Pan) AddTransfer(bytes uint64) {
	p.transfered += bytes
}

func (p *Pan) ResetTransfered() {
	p.transfered = 0
}

func (p *Pan) Age() time.Duration {
	return time.Now().Sub(p.opened)
}

// Creates an LRU cache for only purpose of collecting statitics about the
// connections currently active.
func PanopticonInfo() chan *Pan {
	lru, err := lru.New(500)
	if err != nil {
		log.Printf("Error creating LRU: %#v", err)
	}
	panIn := make(chan *Pan)

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-ticker.C:
				//Process the LRU cache and display data
				log.Infof("########################################################")
				if pans, err := CacheTopTransfer(lru); err == nil {
					plen := len(pans)
					panslen := plen
					log.Debugf("Pans found in PanInfo cache: %d", panslen)
					log.Debugf("Goroutines running:          %d", runtime.NumGoroutine())

					panLimit := 10
					if plen > panLimit {
						plen = panLimit
					}
					for i := 0; i < plen; i++ {
						j := panslen - 1 - i
						log.Infof("%-16s -> %16s :: %s :: %8f :: [%d]%#v", pans[j].src, pans[j].dst, pans[j].opened, pans[j].gv.Mean(), len(*pans[j].gv), *pans[j].gv)

						//Purge cache
						lru.Purge()
					}
				}
			case p := <-panIn:
				lru.Add(p.String(), p)
			}
		}
	}()

	return panIn
}

//Iterate over all IPkeys in the LRU Cache and extract their Pan struct
// for analysis. Returns a list of Pans sorted by their data Transfered.
func CacheTopTransfer(l *lru.Cache) ([]*Pan, error) {
	keys := l.Keys()

	//Compile list of Pan references
	pancons := []*Pan{}
	for _, k := range keys {
		if p, ok := l.Get(k); ok {
			P := p.(*Pan)
			/*
				//Calculate if there's been recent transfer on this stream
				plen := len(*P.gv)
				recentTransfer := 0.0
				//Check the last 30 seconds for any transfer; if none skip
				for i := 1; i < 7; i++ {
					gv := *P.gv
					recentTransfer += gv[plen-i]
				}

				//if recent transfer add to list for sorting.
				if recentTransfer > 0 {
					pancons = append(pancons, P)
				}
			*/
			pancons = append(pancons, P)
		} else {
			return nil, OpticonError{time.Now(), fmt.Sprintf("Failed to Get[%s] from LRU cache", k)}
		}
	}

	sort.Sort(Opticon(pancons))
	return pancons, nil
}

func FilterExternal(pm *types.PacketManifest) *types.PacketManifest {
	if pm.IP.DstIP.String() != ipv4Str {
		return nil
	}
	return pm
}
