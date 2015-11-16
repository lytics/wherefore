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

package types

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lytics/anomalyzer"
)

type SnifferDriverOptions struct {
	DAQ              string
	Filename         string
	Device           string
	Snaplen          int32
	WireDuration     time.Duration
	Filter           string
	TransferInterval string
	AnomalyzerConf   *anomalyzer.AnomalyzerConf
	AlerterConf      *AlertingConf
	FilterIpCIDR     string
	FilterBool       bool
	FilterSrc        bool
	FilterDst        bool
	LogDir           string
}

type FilterDriverOptions struct {
	DAQ              string
	Filename         string
	Device           string
	Snaplen          int32
	WireDuration     time.Duration
	Filter           string
	TransferInterval string
	AnomalyzerConf   *anomalyzer.AnomalyzerConf
	AlerterConf      *AlertingConf
	FilterIpCIDR     string
	FilterBool       bool
	FilterSrc        bool
	FilterDst        bool
	LogDir           string
}

type AlertingConf struct {
	SlackConf map[string]string
	//OpsGenie conf
	//MozDef conf
}

// PacketDataSource is an interface for some source of packet data.
type PacketDataSourceCloser interface {
	// ReadPacketData returns the next packet available from this data source.
	// It returns:
	//  data:  The bytes of an individual packet.
	//  ci:  Metadata about the capture
	//  err:  An error encountered while reading packet data.  If err != nil,
	//    then data/ci will be ignored.
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	// Close closes the ethernet sniffer and returns nil if no error was found.
	Close() error
}

type Supervisor interface {
	Stopped()
	Run()
}

type PacketSource interface {
	Start()
	Stop()
	SetSupervisor(Supervisor)
	GetStartedChan() chan bool // used for unit tests
}

// PacketManifest is used to send parsed packets via channels to other goroutines
type PacketManifest struct {
	Timestamp     time.Time
	Flow          *TcpIpFlow
	RawPacket     []byte
	DecodedLayers []gopacket.LayerType
	Eth           layers.Ethernet
	IP            layers.IPv4
	IPv4          layers.IPv4
	IPv6          layers.IPv6
	TCP           layers.TCP
	UDP           layers.UDP
	Payload       gopacket.Payload
}
