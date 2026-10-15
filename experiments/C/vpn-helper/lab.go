package main

import (
	"errors"
	easyconnect "github.com/mythologyli/zju-connect/client/easyconnect"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
)

var labProfile = "C"
var labMTU = "1400"
var labMu sync.Mutex
var labFirst = ""

func labError(area string, err error) {
	kind := "OTHER"
	switch {
	case errors.Is(err, io.EOF):
		kind = "EOF"
	case errors.Is(err, io.ErrUnexpectedEOF):
		kind = "TRUNCATED"
	case errors.Is(err, syscall.ECONNRESET):
		kind = "TCP_RESET"
	case errors.Is(err, syscall.EMSGSIZE):
		kind = "TOO_LARGE"
	case errors.Is(err, syscall.EPIPE):
		kind = "BROKEN_PIPE"
	case errors.Is(err, easyconnect.ErrSangforShutdown):
		kind = "SHUTDOWN_08"
	case errors.Is(err, easyconnect.ErrSangforReconnectLater):
		kind = "RECONNECT_LATER"
	default:
		var n net.Error
		if errors.As(err, &n) && n.Timeout() {
			kind = "TIMEOUT"
		}
		if strings.Contains(err.Error(), "bad record MAC") {
			kind = "TLS_MAC"
		}
	}
	labMu.Lock()
	if labFirst == "" {
		labFirst = area + "_" + kind
	}
	labMu.Unlock()
}
func labFailure(code string) string {
	labMu.Lock()
	defer labMu.Unlock()
	return "LAB_" + labProfile + "_" + code + "_FIRST_" + labFirst
}
func normalizeLabPacket(p []byte) {}
