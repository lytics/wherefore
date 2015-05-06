/*
 *    HoneyBadger core library for detecting TCP injection attacks
 *
 *    Copyright (C) 2014, 2015  David Stainton
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
	"log"
	"time"

	"github.com/david415/HoneyBadger/types"
)

type TimedRawPacket struct {
	Timestamp time.Time
	RawPacket []byte
}

// InquisitorOptions are user set parameters for specifying the
// details of how to proceed with honey_bager's TCP connection monitoring.
// More parameters should soon be added here!
type DispatcherOptions struct {
	BufferedPerConnection    int
	BufferedTotal            int
	LogDir                   string
	LogPackets               bool
	TcpIdleTimeout           time.Duration
	MaxRingPackets           int
	Logger                   types.Logger
	DetectHijack             bool
	DetectInjection          bool
	DetectCoalesceInjection  bool
	MaxConcurrentConnections int
}

// Inquisitor sets up the connection pool and is an abstraction layer for dealing
// with incoming packets weather they be from a pcap file or directly off the wire.
type Dispatcher struct {
	options                 DispatcherOptions
	connectionFactory       ConnectionFactory
	observeConnectionCount  int
	observeConnectionChan   chan bool
	dispatchPacketChan      chan *types.PacketManifest
	stopDispatchChan        chan bool
	closeConnectionChan     chan ConnectionInterface
	pool                    map[types.ConnectionHash]ConnectionInterface
	pager                   *Pager
	PacketLoggerFactoryFunc func(string, *types.TcpIpFlow) types.PacketLogger
}

// NewInquisitor creates a new Inquisitor struct
func NewDispatcher(options DispatcherOptions, connectionFactory ConnectionFactory, packetLoggerFactoryFunc func(string, *types.TcpIpFlow) types.PacketLogger) *Dispatcher {
	i := Dispatcher{
		PacketLoggerFactoryFunc: packetLoggerFactoryFunc,
		connectionFactory:       connectionFactory,
		options:                 options,
		dispatchPacketChan:      make(chan *types.PacketManifest),
		stopDispatchChan:        make(chan bool),
		closeConnectionChan:     make(chan ConnectionInterface),
		pager:                   NewPager(),
		pool:                    make(map[types.ConnectionHash]ConnectionInterface),
		observeConnectionChan: make(chan bool, 0),
	}
	return &i
}

func (i *Dispatcher) GetObservedConnectionsChan(count int) chan bool {
	i.observeConnectionCount = count
	return i.observeConnectionChan
}

// Start... starts the TCP attack inquisition!
func (i *Dispatcher) Start() {
	i.pager.Start()
	go i.dispatchPackets()
}

// Stop... stops the TCP attack inquisition!
func (i *Dispatcher) Stop() {
	i.stopDispatchChan <- true
	closedConns := i.CloseAllConnections()
	log.Printf("%d connection(s) closed.", closedConns)
	i.pager.Stop()
}

// connectionsLocked returns a slice of Connection pointers.
func (i *Dispatcher) Connections() []ConnectionInterface {
	conns := make([]ConnectionInterface, 0, len(i.pool))
	for _, conn := range i.pool {
		conns = append(conns, conn)
	}
	return conns
}

func (i *Dispatcher) CloseRequest(conn ConnectionInterface) {
	i.closeConnectionChan <- conn
}

func (i *Dispatcher) ReceivePacket(p *types.PacketManifest) {
	i.dispatchPacketChan <- p
}

// CloseOlderThan takes a Time argument and closes all the connections
// that have not received packet since that specified time
func (i *Dispatcher) CloseOlderThan(t time.Time) int {
	closed := 0
	conns := i.Connections()
	if conns == nil {
		return 0
	}
	for _, conn := range conns {
		lastSeen := conn.GetLastSeen()
		if lastSeen.Equal(t) || lastSeen.Before(t) {
			conn.Close()
			delete(i.pool, conn.GetConnectionHash())
			closed += 1
		}
	}
	return closed
}

// CloseAllConnections closes all connections in the pool.
func (i *Dispatcher) CloseAllConnections() int {
	conns := i.Connections()
	if conns == nil {
		return 0
	}
	count := 0
	for _, conn := range conns {
		conn.Close()
		delete(i.pool, conn.GetConnectionHash())
		count += 1
	}
	return count
}

func (i *Dispatcher) setupNewConnection(flow *types.TcpIpFlow) ConnectionInterface {
	options := ConnectionOptions{
		MaxBufferedPagesTotal:         i.options.BufferedTotal,
		MaxBufferedPagesPerConnection: i.options.BufferedPerConnection,
		MaxRingPackets:                i.options.MaxRingPackets,
		Pager:                         i.pager,
		LogDir:                        i.options.LogDir,
		AttackLogger:                  i.options.Logger,
		LogPackets:                    i.options.LogPackets,
		DetectHijack:                  i.options.DetectHijack,
		DetectInjection:               i.options.DetectInjection,
		DetectCoalesceInjection:       i.options.DetectCoalesceInjection,
		Dispatcher:                    i,
	}

	conn := i.connectionFactory.Build(options)

	if i.options.LogPackets {
		packetLogger := i.PacketLoggerFactoryFunc(i.options.LogDir, flow)
		conn.SetPacketLogger(packetLogger)
		packetLogger.Start()
	}
	i.pool[flow.ConnectionHash()] = conn
	conn.Open()
	if i.observeConnectionCount != 0 && i.observeConnectionCount == len(i.Connections()) {
		i.observeConnectionChan <- true
	}
	return conn
}

func (i *Dispatcher) dispatchPackets() {
	var conn ConnectionInterface
	timeout := i.options.TcpIdleTimeout
	ticker := time.Tick(timeout)
	for {
		select {
		case conn := <-i.closeConnectionChan:
			conn.Close()
			delete(i.pool, conn.GetConnectionHash())
		default:
		}
		select {
		case <-ticker:
			closed := i.CloseOlderThan(time.Now().Add(timeout * -1))
			if closed != 0 {
				log.Printf("timeout closed %d connections\n", closed)
			}
		case <-i.stopDispatchChan:
			return
		case packetManifest := <-i.dispatchPacketChan:
			_, ok := i.pool[packetManifest.Flow.ConnectionHash()]
			if ok {
				conn = i.pool[packetManifest.Flow.ConnectionHash()]
			} else {
				if i.options.MaxConcurrentConnections != 0 {
					if len(i.pool) >= i.options.MaxConcurrentConnections {
						continue
					}
				}
				conn = i.setupNewConnection(packetManifest.Flow)
			}
			select {
			case conn.GetReceiveChan() <- packetManifest:
				continue
			case conn = <-i.closeConnectionChan:
				conn.Close()
				delete(i.pool, conn.GetConnectionHash())
			}
		}
	}
}