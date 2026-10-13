//go:build !darwin

package main

import "errors"

func tunControl([]string) error {
	fail("UNSUPPORTED_PLATFORM")
	return errors.New("TUN requires macOS")
}

func tunStdio() error { return errors.New("TUN requires macOS") }
