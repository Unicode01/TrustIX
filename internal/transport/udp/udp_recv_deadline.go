package udp

import "time"

func nowForUDPReadBatch() time.Time {
	return time.Now()
}

func zeroUDPReadDeadline() time.Time {
	return time.Time{}
}
