package stream

import (
	"os"
	"strings"
)

func streamKernelQueueDrainEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_STREAM_KERNEL_QUEUE_DRAIN"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	case "":
		return streamKernelQueueDrainDefault()
	default:
		return false
	}
}
