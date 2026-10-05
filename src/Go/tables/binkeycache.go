package tables

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
)

var key_head, _ = hex.DecodeString("d0502599940b206154ca25cce6ded24ef5aab448e2c209b4a1bcb61295f9eede")
var key_sum, _ = hex.DecodeString("503ff0147ec336e54e1c21c42578e278dddfcdb93e64493d7e7a31c3d537de51")

func ReadKeyCache() ([]byte, [32]byte) {
	ks := [32]byte{}
	copy(ks[:], key_sum)
	return key_head, ks
}

func FindKeyCache(KnownLayout Layout, steamPath string, binCount int) (*[]byte, *[32]byte, error) {
	t, err := NewTables(filepath.Join(steamPath, "MBTL.exe"), KnownLayout, binCount)
	if err != nil {
		return nil, nil, err
	}
	head := t.Key[:32]
	sum := sha256.Sum256(t.Key)

	return &head, &sum, nil
}
