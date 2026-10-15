package easyconnect

import (
	"net"
	"testing"
)

func TestMissingProtoHTTPResourceHasNarrowTCPPermission(t *testing.T) {
	c := NewClient(Options{Resources: ResourceOptions{Fetch: true, IncludeDomains: true}})
	defer c.Close()
	_ = c.parseResources(`<Resource><Rcs><Rc type="1" svc="http" host="198.51.100.2" port="80~80"/></Rcs></Resource>`)
	if len(c.ipResources) != 1 || c.ipResources[0].Protocol != "tcp" {
		t.Fatal("HTTP transport not inferred from explicit service")
	}
	acl := NewResourceACL(c.ipResources)
	if !acl.Matches(net.ParseIP("198.51.100.2"), "tcp", 80) || acl.Matches(net.ParseIP("198.51.100.2"), "tcp", 443) || acl.Matches(net.ParseIP("198.51.100.2"), "udp", 80) {
		t.Fatal("HTTP permission widened")
	}
}
