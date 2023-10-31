// Package otp implements the RFC 4226 (HOTP) and RFC 6238 (TOTP) standards for
// one-time password generation and validation. It provides functions to
// generate and validate HMAC-Based and Time-Based One-Time Passwords using a
// shared secret key.
//
// Example usage:
//
//	import "github.com/sshilin/otp"
//
//	key := []byte("secret")
//	counter := 123
//
//	// Generate an HOTP code
//	hotp := NewHotp()
//	code := hotp.Generate(key, counter))
//
//	// Validate an HOTP code
//	isValid := hotp.Validate(key, code, counter)
//
//	// Generate a TOTP code
//	totp := NewTotp()
//	code := hotp.Generate(key, totp.At(time.Now()))
//
//	// Validate a TOTP code
//	isValid := hotp.Validate(key, code, totp.At(time.Now()))
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"time"
)

// Counter represents the moving factor value used in RFC 4226 (HOTP) standard.
// Counter must increment with each OTP generation to produce a unique code.
type Counter uint64

type hotp struct {
	digits   int
	hashFunc func() hash.Hash
}

type totp struct {
	timeStep int
	epoch    Counter
}

func defaultHotp() *hotp {
	return &hotp{
		hashFunc: sha1.New,
		digits:   6,
	}
}

func defaultTotp() *totp {
	return &totp{
		timeStep: 30,
	}
}

// NewHotp creates a new HOTP instance for generating HMAC-Based OTP codes
func NewHotp(opts ...func(*hotp)) *hotp {
	hp := defaultHotp()
	for _, opt := range opts {
		opt(hp)
	}

	return hp
}

// NewTotp creates a new TOTP instance for generating Time-Based OTP codes
func NewTotp(opts ...func(*totp)) *totp {
	tp := defaultTotp()
	for _, opt := range opts {
		opt(tp)
	}

	return tp
}

// WithDigits configures the number of decimal digits in the OTP code. RFC 4226
// specifies the code length in between 6 to 9 digits. Default: 6 digits.
func WithDigits(n int) func(*hotp) {
	return func(hp *hotp) {
		hp.digits = n
	}
}

// WithHash configures the hashing function to be used for generating OTP codes.
// RFC 4226 specifies sha1 (default), sha256, and sha512 options.
func WithHash(f func() hash.Hash) func(*hotp) {
	return func(hp *hotp) {
		hp.hashFunc = f
	}
}

// WithEpoch configures the initial epoch (t0) to start counting time steps.
// Default: 0 (the Unix epoch)
func WithEpoch(epoch Counter) func(*totp) {
	return func(tp *totp) {
		tp.epoch = epoch
	}
}

// WithTimeStep configures the time step duration. Default: 30 seconds.
func WithTimeStep(step time.Duration) func(*totp) {
	return func(tp *totp) {
		tp.timeStep = int(step.Seconds())
	}
}

// Validate validates an OTP code against the secret key and the counter value.
// This function checks if the provided code matches the expected OTP code for
// the given parameters.
func (hp *hotp) Validate(key []byte, code string, counter Counter) bool {
	return code == hp.Generate(key, counter)
}

// Generate generates an OTP code using the given secret key and the counter
// value. Returns the code as a string.
func (hp *hotp) Generate(key []byte, counter Counter) string {
	mac := hmac.New(hp.hashFunc, key)
	mac.Write(toBinary(uint64(counter)))
	code := truncate(mac.Sum(nil), hp.digits)

	return fmt.Sprintf("%0*d", hp.digits, code)
}

// At calculates the counter value for TOTP code generation. TOTP uses the
// counter that represents time periods since the initial epoch.
func (tp *totp) At(t time.Time) Counter {
	return Counter((uint64(t.Unix()) - uint64(tp.epoch)) / uint64(tp.timeStep))
}

func toBinary(val uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)

	return buf
}

func truncate(digest []byte, digits int) int {
	offset := digest[len(digest)-1] & 0xf
	binary := int(digest[offset]&0x7f)<<24 |
		int(digest[offset+1]&0xff)<<16 |
		int(digest[offset+2]&0xff)<<8 |
		int(digest[offset+3]&0xff)

	return binary % int(math.Pow10(digits))
}
