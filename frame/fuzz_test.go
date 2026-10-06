package frame

import (
	"math"
	"testing"
)

func FuzzDecrypt(f *testing.F) {
	key := make([]byte, keyLen)
	valid, err := Encrypt(EncryptParams{
		Plaintext:         []byte("opus frame payload"),
		Key:               key,
		TruncatedNonce:    1,
		UnencryptedRanges: []Range{{0, 4}},
	})
	if err != nil {
		f.Fatalf("encrypt error: %v", err)
	}
	f.Add(valid)
	f.Add(rangeOffsetOverflowFrame())
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = Decrypt(DecryptParams{Ciphertext: data, Key: key})
	})
}

func FuzzEncrypt(f *testing.F) {
	key := make([]byte, keyLen)
	f.Add([]byte("opus frame payload"), 0, 4)
	f.Add([]byte("opus frame payload"), math.MaxInt, 1)

	f.Fuzz(func(_ *testing.T, plaintext []byte, offset, length int) {
		_, _ = Encrypt(EncryptParams{
			Plaintext:         plaintext,
			Key:               key,
			TruncatedNonce:    1,
			UnencryptedRanges: []Range{{offset, length}},
		})
	})
}
