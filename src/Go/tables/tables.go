package tables

import (
	"fmt"
	"rearc-bintool/encryption"
)

type Layout struct {
	Bounds, Paths, Sizes, Offsets, Key uint64 // VAs
}

type Tables struct {
	Bounds  []uint32
	Paths   []string
	Sizes   []uint32
	Offsets []uint32
	Key     []byte
}

const Bin_Count = 21

func NewTables(path string, l Layout) (*Tables, error) {
	t := &Tables{}
	m, err := NewPEMapper(path)
	if err != nil {
		return nil, err
	}
	defer m.Close()

	// error checks
	if t.Bounds, err = m.ReadU32s(l.Bounds, Bin_Count+1); err != nil {
		return nil, fmt.Errorf("bonds: %w", err)
	}
	if t.Bounds[0] != 0 {
		return nil, fmt.Errorf("bounds[0] = %d, expected 0", t.Bounds[0])
	}

	for i := 1; i < len(t.Bounds); i++ {
		if t.Bounds[i] < t.Bounds[i-1] {
			return nil, fmt.Errorf("bounds decrease at index %d", i)
		}
	}

	count := int(t.Bounds[Bin_Count])

	if t.Sizes, err = m.ReadU32s(l.Sizes, count); err != nil {
		return nil, fmt.Errorf("sizes: %w", err)
	}
	if t.Offsets, err = m.ReadU32s(l.Offsets, count); err != nil {
		return nil, fmt.Errorf("offsets: %w", err)
	}

	ptrs, err := m.ReadU32s(l.Paths, count)
	if err != nil {
		return nil, fmt.Errorf("path pointers: %w", err)
	}
	t.Paths = make([]string, count)
	for i, p := range ptrs {
		if t.Paths[i], err = m.ReadCString(uint64(p)); err != nil {
			return nil, fmt.Errorf("path %d: %w", i, err)
		}
	}

	if t.Key, err = m.ReadBytesAtVA(l.Key, encryption.Table_Size); err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	return t, nil
}
