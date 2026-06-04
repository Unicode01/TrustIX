package daemon

import (
	"io"
	"net/http"
)

const responseDrainLimit = 64 << 10

func drainAndCloseResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, resp.Body, responseDrainLimit)
	_ = resp.Body.Close()
}
