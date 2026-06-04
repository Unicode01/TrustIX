// Package adminauth defines the signed management API request envelope.
package adminauth

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

const (
	Version         = "TRUSTIX-ADMIN-V1"
	HeaderCert      = "X-TrustIX-Admin-Cert"
	HeaderSignature = "X-TrustIX-Admin-Signature"
	HeaderTimestamp = "X-TrustIX-Admin-Timestamp"
)

func SigningBytes(method, requestURI, timestamp string, body []byte) []byte {
	bodyHash := sha256.Sum256(body)
	return SigningBytesForBodyHash(method, requestURI, timestamp, fmt.Sprintf("%x", bodyHash[:]))
}

func SigningBytesForBodyHash(method, requestURI, timestamp, bodyHash string) []byte {
	var builder strings.Builder
	builder.WriteString(Version)
	builder.WriteByte('\n')
	builder.WriteString(strings.ToUpper(method))
	builder.WriteByte('\n')
	builder.WriteString(requestURI)
	builder.WriteByte('\n')
	builder.WriteString(timestamp)
	builder.WriteByte('\n')
	builder.WriteString(strings.ToLower(bodyHash))
	return []byte(builder.String())
}
