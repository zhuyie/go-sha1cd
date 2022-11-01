package sha1cd

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"testing"
)

type sha1Test struct {
	out string
	in  string
}

var golden = []sha1Test{
	{"da39a3ee5e6b4b0d3255bfef95601890afd80709", ""},
	{"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a"},
	{"da23614e02469a0d7c7bd1bdab5c9c474b1904dc", "ab"},
	{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	{"81fe8bfe87576c3ecb22426f8e57847382917acf", "abcd"},
	{"03de6c570bfe24bfc328ccd7ca46b76eadaf4334", "abcde"},
	{"1f8ac10f23c5b5bc1167bda84b833e5c057a77d2", "abcdef"},
	{"2fb5e13419fc89246865e7a324f476ec624e8740", "abcdefg"},
	{"425af12a0743502b322e93a015bcf868e324d56a", "abcdefgh"},
	{"c63b19f1e4c8b5f76b25c49b8b87f57d8e4872a1", "abcdefghi"},
	{"d68c19a0a345b7eab78d5e11e991c026ec60db63", "abcdefghij"},
	{"b7bc5fb91080c7de6b582ea281f8a396d7c0aee8", "The days of the digital watch are numbered.  -Tom Stoppard"},
	{"6859733b2590a8a091cecf50086febc5ceef1e80", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"},
	{"514b2630ec089b8aee18795fc0cf1f4860cdacad", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		h := New()
		h.Write([]byte(g.in))
		s := fmt.Sprintf("%x", h.Sum(nil))
		if s != g.out {
			t.Fatalf("sha1(%s) = %s want %s", g.in, s, g.out)
		}
	}
}

func TestSize(t *testing.T) {
	s := New()
	if got := s.Size(); got != Size {
		t.Errorf("Size = %d; want %d", got, Size)
	}
}

func TestBlockSize(t *testing.T) {
	s := New()
	if got := s.BlockSize(); got != BlockSize {
		t.Errorf("BlockSize = %d; want %d", got, BlockSize)
	}
}

func benchmarkRun(h hash.Hash, i int, b *testing.B) {
	bs := make([]byte, i)
	_, err := rand.Read(bs)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.SetBytes(int64(i))
	for i := 0; i < b.N; i++ {
		h.Write(bs)
		h.Sum(nil)
	}
}

func BenchmarkSHA1CD_1k(b *testing.B) {
	benchmarkRun(New(), 1024, b)
}

func BenchmarkSHA1CD_10k(b *testing.B) {
	benchmarkRun(New(), 10*1024, b)
}

func BenchmarkSHA1CD_100k(b *testing.B) {
	benchmarkRun(New(), 100*1024, b)
}

func BenchmarkSHA1CD_1000k(b *testing.B) {
	benchmarkRun(New(), 1000*1024, b)
}

func BenchmarkSHA1_1k(b *testing.B) {
	benchmarkRun(sha1.New(), 1024, b)
}

func BenchmarkSHA1_10k(b *testing.B) {
	benchmarkRun(sha1.New(), 10*1024, b)
}

func BenchmarkSHA1_100k(b *testing.B) {
	benchmarkRun(sha1.New(), 100*1024, b)
}

func BenchmarkSHA1_1000k(b *testing.B) {
	benchmarkRun(sha1.New(), 1000*1024, b)
}

func BenchmarkSHA256_1k(b *testing.B) {
	benchmarkRun(sha256.New(), 1024, b)
}

func BenchmarkSHA256_10k(b *testing.B) {
	benchmarkRun(sha256.New(), 10*1024, b)
}

func BenchmarkSHA256_100k(b *testing.B) {
	benchmarkRun(sha256.New(), 100*1024, b)
}

func BenchmarkSHA256_1000k(b *testing.B) {
	benchmarkRun(sha256.New(), 1000*1024, b)
}
