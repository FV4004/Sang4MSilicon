package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestLabFirstFailurePreservesDirectionAndHidesErrorText(t *testing.T) {
	labMu.Lock()
	saved := labFirst
	labFirst = ""
	labMu.Unlock()
	t.Cleanup(func() { labMu.Lock(); labFirst = saved; labMu.Unlock() })
	labError("RECV_DATA", fmt.Errorf("sensitive session value: %w", io.ErrUnexpectedEOF))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); labError("SEND_DATA", errors.New("private password and address")) }()
	}
	wg.Wait()
	got := labFailure("TUN_SERVER_SHUTDOWN")
	want := "LAB_" + labProfile + "_TUN_SERVER_SHUTDOWN_FIRST_RECV_DATA_TRUNCATED"
	if got != want || strings.Contains(got, "private") || strings.Contains(got, "session") {
		t.Fatalf("unexpected public diagnostic %q", got)
	}
}
