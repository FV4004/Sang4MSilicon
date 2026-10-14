from pathlib import Path

def apply(dest):
    def change(name,old,new):
        p=dest/'client/easyconnect'/name;s=p.read_text()
        if s.count(old)!=1:raise SystemExit(f'Session refresh anchor mismatch: {name}')
        p.write_text(s.replace(old,new))
    change('client.go','type Options struct {','type Options struct {\n DisableSessionUpdate bool\n SessionDiagnostic func(string)')
    change('client.go','type Client struct {','type Client struct {\n disableSessionUpdate bool\n sessionDiagnostic func(string)')
    change('client.go','c := &Client{','c := &Client{\n disableSessionUpdate:options.DisableSessionUpdate,\n sessionDiagnostic:options.SessionDiagnostic,')
    change('client.go','func (c *Client) sessionKeepAliveLoop() {','func (c *Client) sessionKeepAliveLoop() {\n if c.disableSessionUpdate { c.notifySession("REFRESH_DISABLED"); return }\n c.notifySession("REFRESH_ENABLED")')
    change('client.go','func (c *Client) runSessionKeepAlive(ticks <-chan time.Time, requestTimeout time.Duration) {','func (c *Client) runSessionKeepAlive(ticks <-chan time.Time, requestTimeout time.Duration) {\n if c.disableSessionUpdate { c.notifySession("REFRESH_DISABLED"); return }')
    change('client.go','err := c.requestUpdateSession(ctx)','c.notifySession("REFRESH_BEGIN")\n\t\t\terr := c.requestUpdateSession(ctx)\n if err==nil { c.notifySession("REFRESH_OK") } else { c.notifySession("REFRESH_ERROR") }')
    p=dest/'client/easyconnect/request.go';s=p.read_text();a=s.index('func (c *Client) requestUpdateSession(');b=s.index('\nfunc ',a+5);segment=s[a:b]
    needle='defer func(Body io.ReadCloser) {'
    if segment.count(needle)!=1:raise SystemExit('Session response anchor mismatch')
    segment=segment.replace(needle,'for _, cookie := range resp.Cookies() { if cookie.Name=="TWFID" && cookie.Value!=c.twfID { c.notifySession("REFRESH_COOKIE_CHANGED") } }\n\t'+needle,1)
    segment=segment.replace('var reply struct {','var reply struct {\n TwfID string `xml:"TwfID"`',1)
    needle='if reply.Message != "success" || reply.ErrorCode != "1" {'
    segment=segment.replace(needle,'if reply.TwfID!="" && reply.TwfID!=c.twfID { c.notifySession("REFRESH_BODY_CHANGED") }\n\t'+needle,1)
    p.write_text(s[:a]+segment+s[b:])
    (dest/'client/easyconnect/mchip_session_diagnostic.go').write_text('package easyconnect\nfunc(c *Client)notifySession(label string){if c.sessionDiagnostic!=nil{c.sessionDiagnostic(label)}}\n')
