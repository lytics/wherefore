package HoneyBadger

import (
	"net"
	"testing"

	"github.com/bmizerany/assert"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestSetupPan(t *testing.T) {
	/*
		packetManifest := types.PacketManifest{
			Timestamp: time.Now(),
			Flow:      nil,
			RawPacket: nil,
			IP:        ip,
			TCP:       tcp,
			Payload:   payload,
		}
	*/

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	ip0 := net.ParseIP("127.0.0.100")
	ip1 := net.ParseIP("127.0.0.1")
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{},
		&layers.IPv4{SrcIP: ip0, DstIP: ip1},
		&layers.TCP{},
		gopacket.Payload([]byte{1, 2, 3, 4, 5}))
	packetData := buf.Bytes()
	assert.NotEqual(t, packetData, nil)

}

func TestPan(t *testing.T) {
	src, dst := "127.0.0.1", "169.169.0.0"
	p := NewPan(src, dst)

	assert.Equal(t, p.src, src)
	assert.Equal(t, p.dst, dst)

	transBytes := uint64(343)
	p.AddTransfer(transBytes)
	assert.Equal(t, p.transfered, transBytes)
	assert.Equal(t, p.Transfered(), transBytes)

	p.Flush()
	gv := *p.gv
	assert.Equal(t, p.transfered, uint64(0))
	assert.Equal(t, p.Transfered(), uint64(0))
	assert.Equal(t, gv[p.gv.Len()-1], float64(transBytes))
}

func TestPanCapped(t *testing.T) {
	src, dst := "127.0.0.1", "169.169.0.0"
	p := NewPan(src, dst)
	assert.Equal(t, p.gv.Len(), 0)

	assert.Equal(t, p.src, src)
	assert.Equal(t, p.dst, dst)

	transBytes := uint64(343)
	p.AddTransfer(transBytes)
	assert.Equal(t, p.transfered, transBytes)
	assert.Equal(t, p.Transfered(), transBytes)

	p.Flush()
	p.AddTransfer(transBytes)
	p.AddTransfer(transBytes)
	p.Flush()
	gv := *p.gv
	assert.Equal(t, p.transfered, uint64(0))
	assert.Equal(t, p.Transfered(), uint64(0))
	assert.Equal(t, gv[p.gv.Len()-1], float64(2*transBytes))
	assert.Equal(t, p.gv.Len(), 2, "p.gv does not contain two data points")
}
