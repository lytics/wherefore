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
	"fmt"
	"math"
	"net"
	"sort"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/david415/HoneyBadger/types"
	"github.com/drewlanenga/govector"
	"github.com/lytics/anomalyzer"

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

//Watcher function updates data structures for anomaly analysis
func PanWatcher(p *Pan, ac *anomalyzer.AnomalyzerConf) {
	i := 0

	for {
		i++
		select {
		//TODO: Make time interval configurable
		case <-time.After(5 * time.Second):
			p.gv.PushFixed(float64(p.Transfered()))
			p.LastUpdate()
			p.ResetTransfered()
		}
		//Run alert testing over the transfer Vector
		//TODO Replace with configurable interval which matches a full dataset
		if i > 5 {
			prob, _ := anomalyzer.NewAnomalyzer(ac, *p.gv)

			aprob := prob.Eval()

			if aprob > 0.0 {
				log.Infof("Anomalyzer %s score: %v", p.String(), aprob)
			}
			if aprob > 0.5 {
				log.Warnf("%s Anomaly detected! %#v", p.String(), *p.gv)
			}

			i = 0
		}
	}
}

func PanSetup(packetManifest *types.PacketManifest, anomTest chan<- *Pan) chan<- *types.PacketManifest {
	updateChan := make(chan *types.PacketManifest)
	p := NewPan(packetManifest.IP.SrcIP.String(), packetManifest.IP.DstIP.String())

	go func() {

		ticker := time.NewTicker(5 * time.Second)

		for {
			select {
			case <-ticker.C:
				p.updates += 1
				// Run anomalyzer
				if p.updates > 2 {
					p.Flush()
					//Send Pan struct to AnomalyTester()
					anomTest <- p
				}
			case pm := <-updateChan:
				dlen := len(pm.Payload)
				p.AddTransfer(uint64(dlen))
				//log.Infof("Transfered data: %d", p.transfered)
			}
		}
	}()

	return updateChan
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
	gv *govector.Vector
}

func NewPan(src, dst string) *Pan {
	g := make(govector.Vector, 10, 10)
	p := &Pan{src: src, dst: dst, opened: time.Now(), transfered: 0, gv: &g}
	//Start Goroutine to average intake via channel
	//go PanWatcher(p, ac)
	return p
}

func (p *Pan) Flush() {
	p.gv.PushFixed(float64(p.transfered))
	p.LastUpdate()
	p.ResetTransfered()
	p.updates = 0
}

func (p *Pan) String() string {
	return fmt.Sprintf("%15s -- %15s", p.src, p.dst)
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
					if plen > 10 {
						plen = 10
					}
					for i := 0; i < plen; i++ {
						j := panslen - 1 - i
						log.Infof("%-15s -> %15s :: %s :: %8f :: [%d]%#v", pans[j].src, pans[j].dst, pans[j].opened, pans[j].gv.Mean(), len(*pans[j].gv), *pans[j].gv)

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

func CacheInfo(l *lru.Cache) {
	log.Errorf("\nWe're running CacheInfo right? %#v\n", l)
	for {

		select {
		case <-time.After(10 * time.Second):
			//log.Errorf("LRU cache[%d]\nKeys: %#v\n", l.Len(), l.Keys())
			log.Infof("########################################################")
			if pans, err := CacheTopTransfer(l); err == nil {
				plen := len(pans)
				panslen := plen
				if plen > 10 {
					plen = 10
				}
				for i := 0; i < plen; i++ {
					j := panslen - 1 - i
					log.Infof("%-15s -> %15s :: %s :: %8f :: [%d]%#v", pans[j].src, pans[j].dst, pans[j].opened, pans[j].gv.Mean(), len(*pans[j].gv), *pans[j].gv)
				}
			} else {
				log.Errorf("Error finding the top Transfered connections: %v", err)
			}
		}

	}
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
