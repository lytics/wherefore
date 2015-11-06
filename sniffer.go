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
	"bufio"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/Sirupsen/logrus"
	log "github.com/Sirupsen/logrus"
	"github.com/lytics/anomalyzer"
	"github.com/lytics/slackhook"

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

func (i *Sniffer) AlertSlack(alertChan chan *Pan) {
	slackConf := i.options.AlerterConf.SlackConf
	alerter := slackhook.New(slackConf["slackHookURL"])

	for p := range alertChan {
		//log.Warnf("Alerting Slack: %#v", p)
		hname, _ := os.Hostname()
		msgTxt := fmt.Sprintf("wherefore detected anomylous traffic: %s\n", hname)
		msgTxt += DecodeLayersInfo(p.lastPM)
		msgTxt += fmt.Sprintf("%#v\n", p.gv)

		message := &slackhook.Message{
			Text:      msgTxt,
			Channel:   slackConf["slackChannel"],
			IconEmoji: slackConf["slackIconEmoji"],
		}
		log.Debugf("SlackMsg: %#v", message)
		//err := alerter.Simple(fmt.Sprintf("wherefore detected anomylous traffic: %#v", p.String()))
		err := alerter.Send(message)
		if err != nil {
			log.Errorf("Error alerting to slack: %#v", err)
		}
	}
}

//Accepting Pan structs, determine if their contained GoVector shows signs of
// anomalous data.
func (i *Sniffer) AnomalyTester(in <-chan *Pan, info chan *Pan, alertChan chan *Pan) {
	fio, err := os.OpenFile(i.options.LogDir+"/wherefore_anomalies.log", os.O_RDWR|os.O_APPEND|os.O_CREATE, os.FileMode(0644))
	if err != nil {
		log.Errorf("Unable to open anomaly file: %#v", err)
	}
	defer fio.Close()
	fw := bufio.NewWriter(fio)
	loglvl, _ := log.ParseLevel("debug")

	alertLog := &log.Logger{
		Out:       fw,
		Formatter: new(logrus.JSONFormatter),
		Hooks:     make(logrus.LevelHooks),
		Level:     loglvl,
	}

	for p := range in {
		prob, _ := anomalyzer.NewAnomalyzer(i.options.AnomalyzerConf, *p.gv)

		var copyP Pan
		copyP = *p
		info <- &copyP

		aprob := prob.Eval()
		if aprob > 0.3 {
			log.Debugf("Anomalyzer %s score: %v", p.String(), aprob)
		}
		if aprob > 0.6 {
			log.Debugf("%#v: %#v:\n%f", p.String(), p.gv, aprob)
			log.Warnf("Anomaly detected:%s %#v", p.String(), *p.gv)
			layers := DecodeLayersMap(p.lastPM)
			layers["vector"] = *p.gv
			layers["flow"] = p.String()
			alertLog.WithFields(layers).Warnf("Anomaly detected: %s", p.String())
			fw.Flush()
			alertChan <- &copyP
		}
	}
}

//Intakes PacketManifests and hands them to the updater channels for
// PanMonitors if they exist, and creates them if they're new.
func (i *Sniffer) PMMonitor(pm *types.PacketManifest, anomalyTest chan *Pan, closePan chan *PanCtl) {
	//Derive packet key and either update data transfered or
	//  create new Pan struct/goroutine watcher.
	lkey := LRUKey(pm.IP.SrcIP.String(), pm.IP.DstIP.String())

	if pmCtl, ok := i.LRU.Get(lkey); ok {
		// Send the packet manifest to the updater channel
		pmCtl.(*PanCtl).PMchan <- pm
	} else {
		// Create the Pan struct/goroutine
		panCtl := PanRoutine(pm, i.options.TransferInterval, anomalyTest, closePan)
		// Add the returned updater channel into the LRU
		if ok := i.LRU.Add(lkey, panCtl); !ok {
			log.Debugf("lkey created successfully")
		} else {
			log.Errorf("Error creating LRU k-v! %#v", ok)
		}
	}
}

// Accepting PanCtl structs via the passed channel
//  Runs necessary steps to free the Pan from cache and close goroutine
func (i *Sniffer) PanRemover(panCtls chan *PanCtl) {
	for pCtl := range panCtls {
		lkey := LRUKey(pCtl.P.src, pCtl.P.dst)
		log.Debugf("Removing Pan: %s from cache[%d]\n%#v", lkey, i.LRU.Len(), *pCtl.P.gv)
		i.LRU.Remove(lkey)
		close(pCtl.Stop)
	}
}

func (i *Sniffer) decodePackets() {
	var eth layers.Ethernet
	var ip layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload
	anomalyTest := make(chan *Pan)
	alertChan := make(chan *Pan)
	panClose := make(chan *PanCtl)

	//_, IPNet, err := net.ParseCIDR("10.240.0.0/16")
	_, IPNet, err := net.ParseCIDR(i.options.FilterIpCIDR)
	if err != nil {
		log.Errorf("Error parsing CIDR: %#v", err)
	}

	decodedLen := 6
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip, &ipv6, &tcp, &udp, &payload)
	decoded := make([]gopacket.LayerType, 0, decodedLen)

	// Initialize wherefore goroutines
	piChan := PanopticonInfo()
	/*
		for at := 0; at < 10; at++ {
		}
	*/
	go i.AnomalyTester(anomalyTest, piChan, alertChan)
	go i.AlertSlack(alertChan)
	go i.PanRemover(panClose)

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
			dcopy := make([]gopacket.LayerType, decodedLen, decodedLen)
			if dc := copy(dcopy, decoded); dc <= 0 {
				log.Errorf("Copy of decoded layers failed: %d", dc)
				continue
			}
			packetManifest := types.PacketManifest{
				Timestamp:     timedRawPacket.Timestamp,
				Flow:          flow,
				RawPacket:     timedRawPacket.RawPacket,
				DecodedLayers: dcopy,
				Eth:           eth,
				IP:            ip,
				IPv4:          ip,
				IPv6:          ipv6,
				TCP:           tcp,
				UDP:           udp,
				Payload:       payload,
			}

			//Short circut to only watch traffic heading in one direction
			//if FilterExternal(&packetManifest) == nil {
			if i.options.FilterSrc {
				if i.options.FilterBool && IPNet.Contains(packetManifest.IP.SrcIP) {
					continue
				}
			}

			if i.options.FilterDst {
				if i.options.FilterBool && IPNet.Contains(packetManifest.IP.DstIP) {
					continue
				}
			}

			//Pass packet manifest to the PM-Monitor function
			//TODO: Improve the flow around packet processing from the sniffer/splitter
			i.PMMonitor(&packetManifest, anomalyTest, panClose)

		}
	}
}
