package easyconnect

import (
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"net"
)

// ResourceACL exposes the same indexed IP/protocol/port matcher used by the SDK dialer.
type ResourceACL struct{ index *ipresource.Index }

func NewResourceACL(r []client.IPResource) *ResourceACL {
	return &ResourceACL{index: ipresource.New(r)}
}
func (a *ResourceACL) Matches(ip net.IP, protocol string, port int) bool {
	_, ok := a.index.Match(ip, protocol, port)
	return ok
}
