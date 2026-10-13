//go:build darwin

package main

import (
	"encoding/binary"
	"fmt"
	easyconnect "github.com/mythologyli/zju-connect/client/easyconnect"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// This test only runs with explicit opt-in on an isolated macOS CI runner.
func TestNativeUTUNSmoke(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("MCHIP_TUN_SMOKE") != "1" {
		t.Skip("requires isolated root smoke-test mode")
	}
	d, e := openDevice("192.0.2.2")
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	conn, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 0})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	body := []byte("native-utun-test")
	p := packet(make([]byte, 8+len(body)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], net.ParseIP("192.0.2.1").To4())
	copy(p[16:20], net.ParseIP("192.0.2.2").To4())
	binary.BigEndian.PutUint16(p[20:22], 9876)
	binary.BigEndian.PutUint16(p[22:24], uint16(conn.LocalAddr().(*net.UDPAddr).Port))
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(body)))
	copy(p[28:], body)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum > 65535 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	if _, e = d.Write(p); e != nil {
		t.Fatal(e)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 128)
	n, _, e := conn.ReadFromUDP(buf)
	if e != nil || string(buf[:n]) != string(body) {
		t.Fatalf("UTUN -> OS packet injection failed: %v", e)
	}
	name := d.name
	if e = d.Close(); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 20; i++ {
		if _, e = net.InterfaceByName(name); e != nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("UTUN interface persisted after close")
}

func TestGatewayDNSAnswerPreservesPhysicalBypass(t *testing.T) {
	gateway := netip.MustParseAddr("192.0.2.1")
	table := &routeTable{device: "not-a-real-interface", gateways: map[netip.Addr]bool{gateway: true}}
	if e := table.add(netip.PrefixFrom(gateway, 32)); e != nil {
		t.Fatal("gateway DNS response was rejected", e)
	}
	if len(table.prefixes) != 0 {
		t.Fatal("gateway was redirected into TUN")
	}
}

func TestTunnelServerResponsesHaveDistinctActions(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
	}{{easyconnect.ErrSangforShutdown, "TUN_SERVER_SHUTDOWN"}, {easyconnect.ErrSangforReconnectLater, "TUN_RECONNECT_LATER"}, {easyconnect.ErrMChipSessionExpired, "TUN_SESSION_EXPIRED"}} {
		if got := tunnelErrorCode(fmt.Errorf("wrapped: %w", test.err)); got != test.code {
			t.Errorf("%s != %s", got, test.code)
		}
	}
}
