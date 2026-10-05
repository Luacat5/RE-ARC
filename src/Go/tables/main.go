package tables

import (
	"path/filepath"
)

func LayoutForMBTL(steamPath, searchString string, binCount int) (*Layout, error) {
	m, err := NewPEMapper(filepath.Join(steamPath, "MBTL.exe"))
	if err != nil {
		return nil, err
	}
	defer m.Close()

	s, err := NewScanner(m)
	if err != nil {
		return nil, err
	}

	key_head, key_sum := ReadKeyCache()

	l, err := s.Locate(key_head, key_sum, searchString, binCount)
	if err != nil {
		return nil, err
	}

	return &l, nil
}
