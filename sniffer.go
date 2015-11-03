/*
 *    HoneyBadger core library for detecting TCP injection attacks
 *
 *    Copyright (C) 2014  David Stainton
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
	"io"

	log "github.com/Sirupsen/logrus"
	"github.com/lytics/anomalyzer"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/david415/HoneyBadger/drivers"
	"github.com/david415/HoneyBadger/types"
	"github.com/hashicorp/golang-lru"
)

// Sniffer sets up the connection pool and is an abstraction layer for dealing
// with incoming packets weather they be from a pcap file or directly off the wire.
type Sniffer struct {
	options          *types.SnifferDriverOptions
	supervisor       types.Supervisor
	dispatcher       PacketDispatcher
	packetDataSource types.PacketDataSourceCloser
	stopCaptureChan  chan bool
	decodePacketChan chan TimedRawPacket
	stopDecodeChan   chan bool
	LRU              *lru.Cache
}

// NewSniffer creates a new Sniffer struct
func NewSniffer(options *types.SnifferDriverOptions, dispatcher PacketDispatcher) types.PacketSource {
	hlru, err := lru.New(500)
	if err != nil {
		log.Printf("Error creating LRU: %#v", err)
	}
	i := Sniffer{
		dispatcher:       dispatcher,
		options:          options,
		stopCaptureChan:  make(chan bool),
		decodePacketChan: make(chan TimedRawPacket),
		stopDecodeChan:   make(chan bool),
		LRU:              hlru,
	}
	return &i
}

func (i *Sniffer) SetSupervisor(supervisor types.Supervisor) {
	i.supervisor = supervisor
}

func (i *Sniffer) GetStartedChan() chan bool {
	return make(chan bool)
}

// Start... starts the TCP attack inquisition!
func (i *Sniffer) Start() {
	// XXX
	i.setupHandle()

	go i.capturePackets()
	go i.decodePackets()
}

func (i *Sniffer) Stop() {
	i.stopCaptureChan <- true
	i.stopDecodeChan <- true
	if i.packetDataSource != nil {
		i.packetDataSource.Close()
	}
}

func (i *Sniffer) setupHandle() {
	var err error
	var what string

	factory, ok := drivers.Drivers[i.options.DAQ]
	if !ok {
		log.Fatal(fmt.Sprintf("%s Sniffer not supported on this system", i.options.DAQ))
	}
	i.packetDataSource, err = factory(i.options)

	if err != nil {
		panic(err)
	}

	if i.options.Filename != "" {
		what = fmt.Sprintf("file %s", i.options.Filename)
	} else {
		what = fmt.Sprintf("interface %s", i.options.Device)
	}

	log.Printf("Starting %s packet capture on %s", i.options.DAQ, what)
}

func (i *Sniffer) capturePackets() {

	tchan := make(chan TimedRawPacket, 0)
	// XXX does this need a shutdown code path?
	go func() {
		for {
			rawPacket, captureInfo, err := i.packetDataSource.ReadPacketData()
			if err == io.EOF {
				log.Print("ReadPacketData got EOF\n")
				i.Stop()
				close(tchan)
				i.supervisor.Stopped()
				return
			}
			if err != nil {
				continue
			}
			tchan <- TimedRawPacket{
				Timestamp: captureInfo.Timestamp,
				RawPacket: rawPacket,
			}
		}
	}()

	for {
		select {
		case <-i.stopCaptureChan:
			return
		case t := <-tchan:
			i.decodePacketChan <- t
		}
	}
}

//Accepting Pan structs, determine if their contained GoVector shows signs of
// anomalous data.
func (i *Sniffer) AnomalyTester(in <-chan *Pan, info chan *Pan) {
	for p := range in {
		prob, _ := anomalyzer.NewAnomalyzer(i.options.AnomalyzerConf, *p.gv)

		var copyP Pan
		copyP = *p
		info <- &copyP

		aprob := prob.Eval()
		if aprob > 0.0 {
			log.Infof("Anomalyzer %s score: %v", p.String(), aprob)
		}
		if aprob > 0.5 {
			log.Infof("%#v: %#v:\n%f", p.String(), p.gv, aprob)
			log.Warnf("%s Anomaly detected! %#v", p.String(), *p.gv)
		}
	}
}

//Intakes PacketManifests and hands them to the updater channels for
// PanMonitors if they exist, and creates them if they're new.
func (i *Sniffer) PMMonitor(pm *types.PacketManifest, anomalyTest chan *Pan) {
	//Derive packet key and either update data transfered or
	//  create new Pan struct/goroutine watcher.
	lkey := LRUKey(pm.IP.SrcIP.String(), pm.IP.DstIP.String())

	if pmChan, ok := i.LRU.Get(lkey); ok {
		//Send the packet manifest to the updater channel
		pmChan.(chan<- *types.PacketManifest) <- pm
	} else {
		// Create the Pan struct/goroutine
		upChan := PanSetup(pm, anomalyTest)
		// Add the returned updater channel into the LRU
		if ok := i.LRU.Add(lkey, upChan); !ok {
			log.Debugf("lkey created successfully")
		} else {
			log.Errorf("Error creating LRU k-v! %#v", ok)
		}
	}
}

func (i *Sniffer) decodePackets() {
	var eth layers.Ethernet
	var ip layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload
	anomalyTest := make(chan *Pan)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip, &tcp, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)
	//go CacheInfo(i.LRU)
	piChan := PanopticonInfo()
	for at := 0; at < 10; at++ {
		go i.AnomalyTester(anomalyTest, piChan)
	}

	for {
		select {
		case <-i.stopDecodeChan:
			return
		case timedRawPacket := <-i.decodePacketChan:
			newPayload := new(gopacket.Payload)
			payload = *newPayload
			err := parser.DecodeLayers(timedRawPacket.RawPacket, &decoded)
			if err != nil {
				continue
			}
			flow := types.NewTcpIpFlowFromFlows(ip.NetworkFlow(), tcp.TransportFlow())
			packetManifest := types.PacketManifest{
				Timestamp: timedRawPacket.Timestamp,
				Flow:      flow,
				RawPacket: timedRawPacket.RawPacket,
				IP:        ip,
				TCP:       tcp,
				Payload:   payload,
			}

			//Short circut to only watch traffic heading in one direction
			/*if FilterExternal(&packetManifest) == nil {
				continue
			}*/

			//Pass packet manifest to the PM-Monitor function
			i.PMMonitor(&packetManifest, anomalyTest)

		}
	}
}
