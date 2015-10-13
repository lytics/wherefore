package HoneyBadger

import (
	"fmt"
	"net"
	"sort"
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

type Opticon []*Pan

func (o Opticon) Len() int {
	return len(o)
}

func (o Opticon) Swap(i, j int) {
	o[i], o[j] = o[j], o[i]
}

func (o Opticon) Less(i, j int) bool {
	return o[i].transfered < o[j].transfered
}

//Pan objects watch each IP connection's traffic and total its traffic over time
type Pan struct {
	src        string
	dst        string
	opened     time.Time
	transfered uint64
}

type OpticonError struct {
	When time.Time
	What string
}

func (oe OpticonError) Error() string {
	return fmt.Sprintf("%v: %v", oe.When, oe.What)
}

func NewPan(src, dst string) *Pan {
	p := &Pan{opened: time.Now(), transfered: 0}
	return p
}

func (p *Pan) String() string {
	return fmt.Sprintf("%d -- %s", p.transfered, p.opened)
}

func (p *Pan) Transfered() uint64 {
	return p.transfered
}

func (p *Pan) AddTransfer(bytes uint64) {
	p.transfered += bytes
}

func (p *Pan) Age() time.Duration {
	return time.Now().Sub(p.opened)
}

func CacheInfo(l *lru.Cache) {
	log.Errorf("\nWe're running CacheInfo right? %#v\n", l)
	for {

		select {
		case <-time.After(12 * time.Second):
			keys := l.Keys()
			log.Errorf("Keys found for parsing: %#v", keys)
			for _, k := range keys {
				if p, ok := l.Get(k); ok {
					log.Errorf("%-32s ::: %s", k, p.(*Pan).String())
				} else {
					log.Errorf("Failed to Peek key: %s\n", k)
				}
			}
		}

		select {
		case <-time.After(4 * time.Second):
			//log.Errorf("LRU cache[%d]\nKeys: %#v\n", l.Len(), l.Keys())
			if pans, err := CacheTopTransfer(l); err == nil {
				for i := 0; i < 10; i++ {
					j := len(pans) - 1 - i
					log.Infof("%-15s -> %15s :: %s :: %d", pans[j].src, pans[j].dst, pans[j].opened, pans[j].transfered)
				}
			} else {
				log.Errorf("Error finding the top transfered connections: %v", err)
			}
		}

	}
}

func CacheTopTransfer(l *lru.Cache) ([]*Pan, error) {
	keys := l.Keys()

	//Compile list of Pan references
	pancons := []*Pan{}
	for _, k := range keys {
		if p, ok := l.Get(k); ok {
			P := p.(*Pan)
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
