package easyconnect

import "io"

// DiagnosticControlStream exposes only the read direction of the persistent
// virtual-IP control connection to one experimental observer. Its wire framing
// is not inferred from individual Read calls. The Client still owns its lifetime.
func (c *Client) DiagnosticControlStream() io.Reader {
	c.requestIPConnMu.Lock()
	defer c.requestIPConnMu.Unlock()
	return c.requestIPConn
}
