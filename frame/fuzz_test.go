package frame

import (
	"bytes"
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

// FuzzEncryptDecrypt reads ranges from pairs of bytes, each one a gap after
// the previous range and a length, so that most inputs give valid ranges.
func FuzzEncryptDecrypt(f *testing.F) {
	key := make([]byte, keyLen)
	tooManyRanges := bytes.Repeat([]byte{1, 1}, maxSupplSize)
	f.Add([]byte("opus frame payload"), []byte{0, 4})
	f.Add(make([]byte, len(tooManyRanges)), tooManyRanges)

	f.Fuzz(func(t *testing.T, plaintext, rangeData []byte) {
		var ranges []Range
		end := 0
		for i := 0; i+1 < len(rangeData); i += 2 {
			r := Range{end + int(rangeData[i]), int(rangeData[i+1])}
			ranges = append(ranges, r)
			end = r.Offset + r.Length
		}
		encrypted, err := Encrypt(EncryptParams{
			Plaintext:         plaintext,
			Key:               key,
			TruncatedNonce:    1,
			UnencryptedRanges: ranges,
		})
		if err != nil {
			return
		}
		decrypted, _, err := Decrypt(DecryptParams{Ciphertext: encrypted, Key: key})
		if err != nil {
			t.Fatalf("decrypt error: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("got %x, want %x", decrypted, plaintext)
		}
	})
}
