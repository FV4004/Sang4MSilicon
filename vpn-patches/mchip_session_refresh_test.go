package easyconnect

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type refreshRoundTripper func(*http.Request) (*http.Response, error)

func (f refreshRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRefreshDisabledNeverSendsRequest(t *testing.T) {
	calls := 0
	c := NewClient(Options{Server: "example.test:443", SessionID: "0123456789abcdef", DisableSessionUpdate: true})
	defer c.Close()
	c.httpClient.Transport = refreshRoundTripper(func(*http.Request) (*http.Response, error) { calls++; return nil, nil })
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	c.runSessionKeepAlive(ticks, time.Second)
	if calls != 0 {
		t.Fatal("disabled mode sent session mutation request")
	}
}
func TestRefreshEnabledReportsRotationWithoutExposingValues(t *testing.T) {
	var labels []string
	c := NewClient(Options{Server: "example.test:443", SessionID: "0123456789abcdef"})
	defer c.Close()
	c.sessionDiagnostic = func(label string) {
		labels = append(labels, label)
		if label == "REFRESH_OK" {
			c.lifecycleCancel()
		}
	}
	c.httpClient.Transport = refreshRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/por/update_session.csp" || r.URL.Query().Get("twfid") != c.twfID {
			t.Fatal("unexpected session request")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Set-Cookie": []string{"TWFID=private-new-session; Path=/"}}, Body: io.NopCloser(strings.NewReader("<Auth><Message>success</Message><ErrorCode>1</ErrorCode><TwfID>private-body-session</TwfID></Auth>"))}, nil
	})
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	c.runSessionKeepAlive(ticks, time.Second)
	got := strings.Join(labels, ",")
	want := "REFRESH_BEGIN,REFRESH_COOKIE_CHANGED,REFRESH_BODY_CHANGED,REFRESH_OK"
	if got != want || strings.Contains(got, "private") {
		t.Fatal("unexpected diagnostic", got)
	}
	if c.twfID != "0123456789abcdef" {
		t.Fatal("diagnostic rotated client session")
	}
}
