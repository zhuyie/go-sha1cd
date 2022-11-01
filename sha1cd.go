// Package sha1cd implements the hardened version of SHA-1 hash algorithm.
//
// See https://github.com/cr-marcstevens/sha1collisiondetection.
package sha1cd

// #include "sha1collisiondetection/lib/sha1.h"
// #include "sha1collisiondetection/lib/sha1.c"
// #include "sha1collisiondetection/lib/ubc_check.h"
// #include "sha1collisiondetection/lib/ubc_check.c"
import "C"

import (
	"unsafe"
)

// The size of a SHA-1 checksum in bytes.
const Size = 20

// The blocksize of SHA-1 in bytes.
const BlockSize = 64

// SHA1CD implements hash.Hash to computing the SHA1 checksum.
type SHA1CD struct {
	ctx C.SHA1_CTX
	sum [20]byte
}

// New returns a new SHA1CD.
func New() *SHA1CD {
	s := new(SHA1CD)
	s.Reset()
	return s
}

func (s *SHA1CD) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	ptr := (*C.char)(unsafe.Pointer(&p[0]))
	C.SHA1DCUpdate(&s.ctx, ptr, (C.size_t)(len(p)))
	return len(p), nil
}

func (s *SHA1CD) Sum(b []byte) []byte {
	hash := (*C.uchar)(unsafe.Pointer(&s.sum[0]))
	coll := C.SHA1DCFinal(hash, &s.ctx)
	if coll != 0 {
		// TODO
	}
	return append(b, s.sum[:]...)
}

func (s *SHA1CD) Reset() {
	C.SHA1DCInit(&s.ctx)
}

func (s *SHA1CD) Size() int { return Size }

func (s *SHA1CD) BlockSize() int { return BlockSize }
