package easyconnect

import (
	"bufio"
	"errors"
	"io"
	"net/http"
)

func mchipDrainTokenResponses(input io.Reader) error {
	reader := bufio.NewReader(input)
	for i := 0; i < 2; i++ {
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return errors.New("token resource HTTP status not OK")
		}
		n, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 2*1024*1024+1))
		response.Body.Close()
		if readErr != nil {
			return readErr
		}
		if n > 2*1024*1024 {
			return errors.New("token resource response exceeds limit")
		}
	}
	return nil
}
