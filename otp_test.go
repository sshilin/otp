package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
	"time"
)

func TestEpochs(t *testing.T) {
	totp := NewTotp(WithEpoch(0), WithTimeStep(10*time.Second))
	if c := totp.At(time.Unix(0, 0)); c != 0 {
		t.Logf("Expected %d, but was %d", 0, c)
		t.Fail()
	}
	if c := totp.At(time.Unix(9, 0)); c != 0 {
		t.Logf("Expected %d, but was %d", 0, c)
		t.Fail()
	}
	if c := totp.At(time.Unix(10, 0)); c != 1 {
		t.Logf("Expected %d, but was %d", 1, c)
		t.Fail()
	}
	totp = NewTotp(WithEpoch(10), WithTimeStep(10*time.Second))
	if c := totp.At(time.Unix(10, 0)); c != 0 {
		t.Logf("Expected %d, but was %d", 0, c)
		t.Fail()
	}
	if c := totp.At(time.Unix(19, 0)); c != 0 {
		t.Logf("Expected %d, but was %d", 0, c)
		t.Fail()
	}
	if c := totp.At(time.Unix(20, 0)); c != 1 {
		t.Logf("Expected %d, but was %d", 1, c)
		t.Fail()
	}
}

func TestHOTPVectors(t *testing.T) {
	key20 := []byte("12345678901234567890")
	testCases := []struct {
		counter Counter
		code    string
	}{
		{
			counter: 0,
			code:    "755224",
		},
		{
			counter: 1,
			code:    "287082",
		},
		{
			counter: 2,
			code:    "359152",
		},
		{
			counter: 3,
			code:    "969429",
		},
		{
			counter: 4,
			code:    "338314",
		},
		{
			counter: 5,
			code:    "254676",
		},
		{
			counter: 6,
			code:    "287922",
		},
		{
			counter: 7,
			code:    "162583",
		},
		{
			counter: 8,
			code:    "399871",
		},
		{
			counter: 9,
			code:    "520489",
		},
	}
	for _, tC := range testCases {
		t.Run("RFC 4226 Appendix D - HOTP Algorithm: Test Values", func(t *testing.T) {
			hotp := NewHotp()
			code := hotp.Generate(key20, tC.counter)
			if tC.code != code {
				t.Logf("Expected code %s, but was %s", tC.code, code)
				t.Fail()
			}
			if !hotp.Validate(key20, code, tC.counter) {
				t.Logf("Code %s expected to be valid", code)
				t.Fail()
			}
		})
	}
}

func TestTOTPVectors(t *testing.T) {
	key20 := []byte("12345678901234567890")
	key32 := []byte("12345678901234567890123456789012")
	key64 := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	testCases := []struct {
		hashFunc func() hash.Hash
		unixTime time.Time
		key      []byte
		code     string
	}{
		{
			hashFunc: sha1.New,
			unixTime: time.Unix(59, 0),
			key:      key20,
			code:     "94287082",
		},
		{
			hashFunc: sha256.New,
			unixTime: time.Unix(59, 0),
			key:      key32,
			code:     "46119246",
		},
		{
			hashFunc: sha512.New,
			unixTime: time.Unix(59, 0),
			key:      key64,
			code:     "90693936",
		},
		{
			hashFunc: sha1.New,
			unixTime: time.Unix(1111111109, 0),
			key:      key20,
			code:     "07081804",
		},
		{
			hashFunc: sha256.New,
			unixTime: time.Unix(1111111109, 0),
			key:      key32,
			code:     "68084774",
		},
		{
			hashFunc: sha512.New,
			unixTime: time.Unix(1111111109, 0),
			key:      key64,
			code:     "25091201",
		},
		{
			hashFunc: sha1.New,
			unixTime: time.Unix(1111111111, 0),
			key:      key20,
			code:     "14050471",
		},
		{
			hashFunc: sha256.New,
			unixTime: time.Unix(1111111111, 0),
			key:      key32,
			code:     "67062674",
		},
		{
			hashFunc: sha512.New,
			unixTime: time.Unix(1111111111, 0),
			key:      key64,
			code:     "99943326",
		},
		{
			hashFunc: sha1.New,
			unixTime: time.Unix(1234567890, 0),
			key:      key20,
			code:     "89005924",
		},
		{
			hashFunc: sha256.New,
			unixTime: time.Unix(1234567890, 0),
			key:      key32,
			code:     "91819424",
		},
		{
			hashFunc: sha512.New,
			unixTime: time.Unix(1234567890, 0),
			key:      key64,
			code:     "93441116",
		},
		{
			hashFunc: sha1.New,
			unixTime: time.Unix(2000000000, 0),
			key:      key20,
			code:     "69279037",
		},
		{
			hashFunc: sha256.New,
			unixTime: time.Unix(2000000000, 0),
			key:      key32,
			code:     "90698825",
		},
		{
			hashFunc: sha512.New,
			unixTime: time.Unix(2000000000, 0),
			key:      key64,
			code:     "38618901",
		},
		{
			hashFunc: sha1.New,
			unixTime: time.Unix(20000000000, 0),
			key:      key20,
			code:     "65353130",
		},
		{
			hashFunc: sha256.New,
			unixTime: time.Unix(20000000000, 0),
			key:      key32,
			code:     "77737706",
		},
		{
			hashFunc: sha512.New,
			unixTime: time.Unix(20000000000, 0),
			key:      key64,
			code:     "47863826",
		},
	}
	for _, tC := range testCases {
		t.Run("RFC 6238 Appendix B - Test Vectors", func(t *testing.T) {
			hotp := NewHotp(WithHash(tC.hashFunc), WithDigits(8))
			totp := NewTotp()
			code := hotp.Generate(tC.key, totp.At(tC.unixTime))
			if code != tC.code {
				t.Logf("Expected code %s, but was %s", tC.code, code)
				t.Fail()
			}
			if !hotp.Validate(tC.key, code, totp.At(tC.unixTime)) {
				t.Logf("Code %s expected to be valid", code)
				t.Fail()
			}
		})
	}
}
