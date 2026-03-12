package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Code returns an RFC6238 TOTP (SHA1, 6 digits) for the given base32 secret and timestep (usually 30s).
func Code(secret string, t time.Time, step int) (string, error) {
	if step <= 0 {
		step = 30
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix() / int64(step))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0F
	codeInt := (uint32(sum[offset])&0x7F)<<24 | (uint32(sum[offset+1])&0xFF)<<16 | (uint32(sum[offset+2])&0xFF)<<8 | (uint32(sum[offset+3]) & 0xFF)
	codeInt %= 1_000_000
	return fmt.Sprintf("%06d", codeInt), nil
}
