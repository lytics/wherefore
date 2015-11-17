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

package wherefore

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/lytics/anomalyzer"
	"github.com/lytics/slackhook"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/hashicorp/golang-lru"
	"github.com/lytics/wherefore/drivers"
	"github.com/lytics/wherefore/types"
)

// Filter sets up the connection pool and is an abstraction layer for dealing
// with incoming packets weather they be from a pcap file or directly off the wire.
type Filter struct {
	options          *types.FilterDriverOptions
	supervisor       types.Supervisor
	dispatcher       PacketDispatcher
	packetDataSource types.PacketDataSourceCloser
	stopCaptureChan  chan bool
	decodePacketChan chan TimedRawPacket
	stopDecodeChan   chan bool
	LRU              *lru.Cache
}

// NewFilter creates a new Filter struct
func NewFilter(options *types.FilterDriverOptions, dispatcher PacketDispatcher) types.PacketSource {
	hlru, err := lru.New(500)
	if err != nil {
		//No chance of normal functionallity, so panic
		panic(fmt.Sprintf("Error creating LRU: %#v", err))
	}

	i := Filter{
		dispatcher:       dispatcher,
		options:          options,
		stopCaptureChan:  make(chan bool),
		decodePacketChan: make(chan TimedRawPacket),
		stopDecodeChan:   make(chan bool),
		LRU:              hlru,
	}
	return &i
}

func (i *Filter) SetSupervisor(supervisor types.Supervisor) {
	i.supervisor = supervisor
}

func (i *Filter) GetStartedChan() chan bool {
	return make(chan bool)
}

// Start... starts the TCP attack inquisition!
func (i *Filter) Start() {
	// XXX
	i.setupHandle()

	go i.capturePackets()
	go i.decodePackets()
}

func (i *Filter) Stop() {
	i.stopCaptureChan <- true
	i.stopDecodeChan <- true
	if i.packetDataSource != nil {
		i.packetDataSource.Close()
	}
}

func (i *Filter) setupHandle() {
	var err error
	var what string

	factory, ok := drivers.FilterDrivers[i.options.DAQ]
	if !ok {
		log.Fatal(fmt.Sprintf("%s Filter not supported on this system", i.options.DAQ))
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

func (i *Filter) capturePackets() {

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

type AlertMessage struct {
	P      *Pan
	Layers *map[string]interface{}
}

func (i *Filter) AlertSlack(alertChan chan *AlertMessage) {
	slackConf := i.options.AlerterConf.SlackConf
	alerter := slackhook.New(slackConf["slackHookURL"])

	for p := range alertChan {
		//log.Warnf("Alerting Slack: %#v", p)
		hname, _ := os.Hostname()
		layers := *p.Layers
		msgTxt := fmt.Sprintf("wherefore detected anomylous traffic: %s Probability: %f\n", hname, layers["anomaly_probability"])
		msgTxt += DecodeLayersInfo(p.P.lastPM)
		msgTxt += fmt.Sprintf("%#v\n", p.P.gv)

		message := &slackhook.Message{
			Text:      msgTxt,
			Channel:   slackConf["slackChannel"],
			IconEmoji: slackConf["slackIconEmoji"],
		}
		log.Debugf("SlackMsg: %#v", message)
		//err := alerter.Simple(fmt.Sprintf("wherefore detected anomylous traffic: %#v", p.String()))
		err := alerter.Send(message)
		//TODO: Debug why invalid args don't return an error here
		if err != nil {
			log.Errorf("Error alerting to slack: %#v", err)
		}
	}
}

//Accepting Pan structs, determine if their contained GoVector shows signs of
// anomalous data.
func (i *Filter) AnomalyTester(in <-chan *Pan, info chan *Pan, alertChan chan *AlertMessage) {
	fio, err := os.OpenFile(i.options.LogDir+"/wherefore_anomalies.log", os.O_RDWR|os.O_APPEND|os.O_CREATE, os.FileMode(0644))
	if err != nil {
		log.Errorf("Unable to open anomaly file: %#v", err)
		i.Stop()
	}
	defer fio.Close()
	fw := bufio.NewWriter(fio)
	loglvl, _ := log.ParseLevel("debug")

	alertLog := &log.Logger{
		Out:       fw,
		Formatter: new(log.JSONFormatter),
		Hooks:     make(log.LevelHooks),
		Level:     loglvl,
	}

	for p := range in {
		prob, _ := anomalyzer.NewAnomalyzer(i.options.AnomalyzerConf, *p.gv)

		var copyP Pan
		copyP = *p
		info <- &copyP

		aprob := prob.Eval()
		if aprob > 0.3 {

			log.WithFields(log.Fields{
				"probability": aprob,
				"flow":        p.String(),
			}).Debugf("Anomalyzer low score")

		}
		if aprob > 0.6 {
			log.Debugf("%#v: %#v:\n%f", p.String(), p.gv, aprob)
			log.WithFields(log.Fields{
				"flow":     p.String(),
				"govector": *p.gv,
			}).Warnf("Anomaly detected")
			layers := DecodeLayersMap(p.lastPM)
			layers["vector"] = *p.gv
			layers["flow"] = p.String()
			layers["anomaly_probability"] = aprob

			log.WithFields(layers).Warnf("Anomaly Detected")
			alertLog.WithFields(layers).Warnf("Anomaly detected")
			fw.Flush()
			alertChan <- &AlertMessage{P: &copyP, Layers: &layers}
		}
	}
}

//Intakes PacketManifests and hands them to the updater channels for
// PanMonitors if they exist, and creates them if they're new.
func (i *Filter) PMMonitor(pm *types.PacketManifest, anomalyTest chan *Pan, closePan chan *PanCtl) {
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
			log.WithFields(log.Fields{"lruKey": lkey}).Debugf("lkey created successfully")
		} else {
			log.WithFields(log.Fields{"error": ok}).Errorf("Error creating LRU k-v!")
		}
	}
}

// Accepting PanCtl structs via the passed channel
//  Runs necessary steps to free the Pan from cache and close goroutine
func (i *Filter) PanRemover(panCtls chan *PanCtl) {
	for pCtl := range panCtls {
		lkey := LRUKey(pCtl.P.src, pCtl.P.dst)
		log.WithFields(log.Fields{
			"lruKey":      lkey,
			"lruSize":     i.LRU.Len(),
			"panGovector": *pCtl.P.gv,
		}).Debugf("Removing Pan from LRU cache")
		i.LRU.Remove(lkey)
		close(pCtl.Stop)
	}
}

func (i *Filter) decodePackets() {
	var eth layers.Ethernet
	var ip layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload
	anomalyTest := make(chan *Pan)
	alertChan := make(chan *AlertMessage)
	panClose := make(chan *PanCtl)

	//_, IPNet, err := net.ParseCIDR("10.240.0.0/16")
	_, IPNet, err := net.ParseCIDR(i.options.FilterIpCIDR)
	if err != nil {
		log.Errorf("Error parsing CIDR: %#v", err)
		i.Stop()
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
