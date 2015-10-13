package HoneyBadger

import (
	"fmt"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/david415/HoneyBadger/types"

	"github.com/hashicorp/golang-lru"
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

//Panopticon objects watch each IP connection's traffic and total its traffic over time
type Panopticon struct {
	src        string
	dst        string
	opened     time.Time
	transfered uint64
}

func NewPanopticon(src, dst string) *Panopticon {
	p := &Panopticon{opened: time.Now(), transfered: 0}
	return p
}

func (p *Panopticon) String() string {
	return fmt.Sprintf("%d -- %s", p.transfered, p.opened)
}

func (p *Panopticon) Transfered() uint64 {
	return p.transfered
}

func (p *Panopticon) AddTransfer(bytes uint64) {
	p.transfered += bytes
}

func (p *Panopticon) Age() time.Duration {
	return time.Now().Sub(p.opened)
}

func CacheInfo(l *lru.Cache) {
	log.Errorf("\nWe're running CacheInfo right? %#v\n", l)
	for {

		select {
		case <-time.After(21 * time.Second):
			keys := l.Keys()
			log.Errorf("Keys found for parsing: %#v", keys)
			for _, k := range keys {
				if p, ok := l.Get(k); ok {
					log.Errorf("%-32s ::: %s", k, p.(*Panopticon).String())
				} else {
					log.Errorf("Failed to Peek key: %s\n", k)
				}
			}
		}

		select {
		case <-time.After(5 * time.Second):
			log.Errorf("LRU cache[%d]\nKeys: %#v\n", l.Len(), l.Keys())
		}

	}
}

func FilterExternal(pm *types.PacketManifest) *types.PacketManifest {
	if pm.IP.DstIP.String() != ipv4Str {
		return nil
	}
	return pm
}
