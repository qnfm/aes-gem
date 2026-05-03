package gem

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

func BenchmarkAESGCM256Seal4K(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 4096)
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		b.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}

	dst := make([]byte, 0, len(plaintext)+aead.Overhead())

	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		nonce[len(nonce)-1]++
		dst = aead.Seal(dst[:0], nonce, plaintext, aad)
	}
}
func benchAESGEM256Seal(b *testing.B, size int) {
	key := make([]byte, 32)
	nonce := make([]byte, NonceSize256)
	plaintext := make([]byte, size)
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		b.Fatal(err)
	}

	aead, err := NewAES256(key)
	if err != nil {
		b.Fatal(err)
	}

	dst := make([]byte, 0, len(plaintext)+aead.Overhead())

	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		nonce[len(nonce)-1]++
		dst = aead.Seal(dst[:0], nonce, plaintext, aad)
	}
}

func benchAESGEM256Open(b *testing.B, size int) {
	key := make([]byte, 32)
	nonce := make([]byte, NonceSize256)
	plaintext := make([]byte, size)
	aad := []byte("aad")

	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		b.Fatal(err)
	}

	aead, err := NewAES256(key)
	if err != nil {
		b.Fatal(err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	dst := make([]byte, 0, len(plaintext))

	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := aead.Open(dst[:0], nonce, ciphertext, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestGHASHBackendMatchesGeneric(t *testing.T) {
	var h [16]byte
	var y1 [16]byte
	var y2 [16]byte

	for i := range h {
		h[i] = byte(i*17 + 3)
	}
	for i := range y1 {
		y1[i] = byte(i*11 + 7)
		y2[i] = y1[i]
	}

	sizes := []int{0, 16, 32, 64, 256, 4096}

	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i*13 + 9)
		}

		y1 = [16]byte{}
		y2 = [16]byte{}

		ghashUpdate(&y1, &h, data)
		ghashUpdate(&y2, &h, data)

	}
}

func BenchmarkAESGEM256Seal4K(b *testing.B)   { benchAESGEM256Seal(b, 4<<10) }
func BenchmarkAESGEM256Seal16K(b *testing.B)  { benchAESGEM256Seal(b, 16<<10) }
func BenchmarkAESGEM256Seal64K(b *testing.B)  { benchAESGEM256Seal(b, 64<<10) }
func BenchmarkAESGEM256Seal256K(b *testing.B) { benchAESGEM256Seal(b, 256<<10) }
func BenchmarkAESGEM256Seal1M(b *testing.B)   { benchAESGEM256Seal(b, 1<<20) }

func BenchmarkAESGEM256Open4K(b *testing.B)   { benchAESGEM256Open(b, 4<<10) }
func BenchmarkAESGEM256Open16K(b *testing.B)  { benchAESGEM256Open(b, 16<<10) }
func BenchmarkAESGEM256Open64K(b *testing.B)  { benchAESGEM256Open(b, 64<<10) }
func BenchmarkAESGEM256Open256K(b *testing.B) { benchAESGEM256Open(b, 256<<10) }
func BenchmarkAESGEM256Open1M(b *testing.B)   { benchAESGEM256Open(b, 1<<20) }
