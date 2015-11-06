/*    Wherefore main command line tool for monitoring network traffic
 *    on a IP stream basis.
 *    Forked from the HoneyBadger main command line tool
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

package main

import (
	"flag"
	"math"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/lytics/anomalyzer"

	"github.com/david415/HoneyBadger"
	"github.com/david415/HoneyBadger/logging"
	"github.com/david415/HoneyBadger/types"
)

func main() {
	var (
		pcapfile                 = flag.String("pcapfile", "", "pcap filename to read packets from rather than a wire interface.")
		iface                    = flag.String("i", "eth0", "Interface to get packets from")
		snaplen                  = flag.Int("s", 65536, "SnapLen for pcap packet capture")
		filter                   = flag.String("f", "tcp", "BPF filter for pcap")
		logDir                   = flag.String("l", "", "incoming log dir used initially for pcap files if packet logging is enabled")
		logLevel                 = flag.String("loglevel", "info", "LogLevel: 'debug', 'info', 'warn', 'error', 'fatal', 'panic'?")
		wireTimeout              = flag.String("w", "3s", "timeout for reading packets off the wire")
		logPackets               = flag.Bool("log_packets", false, "if set to true then log all packets for each tracked TCP connection")
		transferInterval         = flag.String("transfer_interval", "5s", "Interval in seconds to meansure network flow transfer")
		maxConcurrentConnections = flag.Int("max_concurrent_connections", 0, "Maximum number of concurrent connection to track.")
		bufferedPerConnection    = flag.Int("connection_max_buffer", 0, `
Max packets to buffer for a single connection before skipping over a gap in data
and continuing to stream the connection after the buffer.  If zero or less, this
is infinite.`)
		bufferedTotal = flag.Int("total_max_buffer", 0, `
Max packets to buffer total before skipping over gaps in connections and
continuing to stream connection data.  If zero or less, this is infinite`)
		maxPcapLogSize      = flag.Int("max_pcap_log_size", 1, "maximum pcap size per rotation in megabytes")
		maxNumPcapRotations = flag.Int("max_pcap_rotations", 10, "maximum number of pcap rotations per connection")
		archiveDir          = flag.String("archive_dir", "", "archive directory for storing attack logs and related pcap files")
		daq                 = flag.String("daq", "libpcap", "Data AcQuisition packet source")

		//Filtering Configuration
		filterIpCIDR = flag.String("filter_ip_CIDR", "0.0.0.0/0", "CIDR Mask to allow traffic")
		filterBool   = flag.Bool("filter_bool", true, "Bool operator to use CIDR filter against")
		filterSrc    = flag.Bool("filter_src", true, "Filter packets by their source")
		filterDst    = flag.Bool("filter_dst", true, "Filter packets by their destination")

		//Anomalyzer Configs
		anomSensetivity = flag.Float64("anom_sensitivity", 2.0, "Anomalyzer sensetivity")
		anomUpperBound  = flag.Float64("anom_upper_bound", 5.0, "Anomalyzer UpperBound for Fencing")
		anomLowerBound  = flag.Float64("anom_lower_bound", math.SmallestNonzeroFloat64, "Anomolyzer LowerBound for Fencing")
		anomActiveSize  = flag.Int("anom_active_size", 1, "Anomalyzer Active Size")
		anomNSeasons    = flag.Int("anom_n_seasons", 4, "Anomalyzer N Seasons variable")
		anomMethodsCSL  = flag.String("anom_methods", "diff,fence,highrank,lowrank,magnitude", "Anomalyzer algorithms to test, written in csv format. eg: diff,fence,etc")
		anomGvCap       = flag.Int("anom_gv_cap", 10, "Number of data points to run anomalyzer test over")

		//Slack Alert Configs
		slackChannel   = flag.String("slack_channel", "#wherefore", "Slack Channel to send messages to")
		slackHookURL   = flag.String("slack_url", "nil", "Slack Hook URL")
		slackIconURL   = flag.String("slack_icon", "https://cdn4.iconfinder.com/data/icons/proglyphs-free/512/Invader_1-128.png", "Icon URL for slack message")
		slackIconEmoji = flag.String("slack_emoji", ":warning:", "Emoji icon to use for icon instead of URL")
	)
	flag.Parse()

	loglvl, _ := log.ParseLevel(*logLevel)
	log.SetLevel(loglvl)

	if *daq == "" {
		log.Fatal("must specify a Data AcQuisition packet source`")
	}

	// XXX TODO use the pure golang pcap file sniffing API; gopacket's pcapgo
	if *pcapfile != "" && *daq != "libpcap" {
		log.Fatal("only libpcap DAQ supports sniffing pcap files")
	}

	if *archiveDir == "" || *logDir == "" {
		log.Fatal("must specify both incoming log dir and archive log dir")
	}

	wireDuration, err := time.ParseDuration(*wireTimeout)
	if err != nil {
		log.Fatal("invalid wire timeout duration: ", *wireTimeout)
	}

	if *maxConcurrentConnections == 0 {
		log.Fatal("maxConcurrentConnections must be specified")
	}

	if *bufferedPerConnection == 0 || *bufferedTotal == 0 {
		log.Fatal("connection_max_buffer and total_max_buffer must be set to a non-zero value")
	}

	anomMethods := strings.Split(*anomMethodsCSL, ",")
	anomConf := &anomalyzer.AnomalyzerConf{
		Sensitivity: *anomSensetivity,
		UpperBound:  *anomUpperBound,
		LowerBound:  *anomLowerBound, // ignore the lower bound
		ActiveSize:  *anomActiveSize,
		NSeasons:    *anomNSeasons,
		Methods:     anomMethods,
		VectorCap:   *anomGvCap,
	}
	log.Debugf("AnomalyzerConf:\n%#v", anomConf)

	slackConf := map[string]string{
		"slackChannel":   *slackChannel,
		"slackHookURL":   *slackHookURL,
		"slackIconURL":   *slackIconURL,
		"slackIconEmoji": *slackIconEmoji,
	}
	alerter := &types.AlertingConf{SlackConf: slackConf}
	snifferDriverOptions := types.SnifferDriverOptions{
		DAQ:              *daq,
		Device:           *iface,
		Filename:         *pcapfile,
		TransferInterval: *transferInterval,
		WireDuration:     wireDuration,
		Snaplen:          int32(*snaplen),
		Filter:           *filter,
		AnomalyzerConf:   anomConf,
		AlerterConf:      alerter,
		FilterIpCIDR:     *filterIpCIDR,
		FilterBool:       *filterBool,
		FilterSrc:        *filterSrc,
		FilterDst:        *filterDst,
		LogDir:           *logDir,
	}
	log.Debugf("Sniffer Options:\n%#v", snifferDriverOptions)

	connectionFactory := &HoneyBadger.DefaultConnFactory{}
	var packetLoggerFactory types.PacketLoggerFactory
	if *logPackets {
		packetLoggerFactory = logging.NewPcapLoggerFactory(*logDir, *archiveDir, *maxNumPcapRotations, *maxPcapLogSize)
	} else {
		packetLoggerFactory = nil
	}

	log.Info("Wherefore: IP stream monitoring and analysis tool")
	options := HoneyBadger.SupervisorOptions{
		SnifferDriverOptions: &snifferDriverOptions,
		SnifferFactory:       HoneyBadger.NewSniffer,
		ConnectionFactory:    connectionFactory,
		PacketLoggerFactory:  packetLoggerFactory,
	}
	supervisor := HoneyBadger.NewSupervisor(options)
	supervisor.Run()
}
