package daemon

import (
	"errors"
	"io"
	"log"
	"net/http"
)

const responseDrainLimit = 64 << 10

func drainAndCloseResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	var cleanupErrs []error
	if _, err := io.CopyN(io.Discard, resp.Body, responseDrainLimit); err != nil && !errors.Is(err, io.EOF) {
		cleanupErrs = append(cleanupErrs, err)
	}
	if err := resp.Body.Close(); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}
	if err := errors.Join(cleanupErrs...); err != nil {
		log.Printf("trustixd: drain and close HTTP client response: %v", err)
	}
}
