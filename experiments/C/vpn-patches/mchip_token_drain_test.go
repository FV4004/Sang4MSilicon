package easyconnect

import (
	"strings"
	"testing"
)

func TestLabTokenDrainCompletesBothResponses(t *testing.T) {
	good := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\noneHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo"
	if err := mchipDrainTokenResponses(strings.NewReader(good)); err != nil {
		t.Fatal(err)
	}
	if err := mchipDrainTokenResponses(strings.NewReader(good[:len(good)-2])); err == nil {
		t.Fatal("truncated body accepted")
	}
}
func TestLabTokenDrainRejectsUnauthorized(t *testing.T) {
	if err := mchipDrainTokenResponses(strings.NewReader("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")); err == nil {
		t.Fatal("unauthorized token response accepted")
	}
}
