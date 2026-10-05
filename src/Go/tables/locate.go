package tables

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"rearc-bintool/encryption"
)

type Scanner struct {
	rd   []byte
	rdVA uint64
}

func NewScanner(m *PEMapper) (*Scanner, error) {
	sec := m.pe.Section(".rdata")
	if sec == nil {
		return nil, errors.New(".rdata section not found")
	}
	data, err := sec.Data()
	if err != nil {
		return nil, err
	}
	return &Scanner{rd: data, rdVA: m.ImageBase + uint64(sec.VirtualAddress)}, nil
}

func (s *Scanner) u32(i int) uint32 { return binary.LittleEndian.Uint32(s.rd[i:]) }
func (s *Scanner) va(i int) uint64  { return s.rdVA + uint64(i) }

func (s *Scanner) idx(va uint64) (int, bool) {
	if va < s.rdVA || va >= s.rdVA+uint64(len(s.rd)) {
		return 0, false
	}
	return int(va - s.rdVA), true
}

func (s *Scanner) u32s(i, n int) []uint32 {
	out := make([]uint32, n)
	for k := range out {
		out[k] = s.u32(i + 4*k)
	}
	return out
}

func (s *Scanner) FindKey(head []byte, sum [32]byte) (uint64, error) {
	var found []int
	for from := 0; from < len(s.rd); {
		i := bytes.Index(s.rd[from:], head)
		if i < 0 {
			break
		}
		i += from
		from = i + 1
		if i+encryption.Table_Size <= len(s.rd) && sha256.Sum256(s.rd[i:i+encryption.Table_Size]) == sum {
			found = append(found, i)
		}
	}
	if len(found) != 1 {
		return 0, fmt.Errorf("key table: %d matches, want 1", len(found))
	}
	return s.va(found[0]), nil
}
func (s *Scanner) FindBounds(n int, total uint32) (int, []uint32, error) {
	var hits []int
	for i := 0; i+4*n <= len(s.rd); i += 4 {
		if s.u32(i) != 0 || s.u32(i+4*(n-1)) != total {
			continue
		}
		prev, ok := uint32(0), true
		for k := 1; k < n; k++ {
			v := s.u32(i + 4*k)
			if v <= prev {
				ok = false
				break
			}
			prev = v
		}
		if ok {
			hits = append(hits, i)
		}
	}
	if len(hits) != 1 {
		return 0, nil, fmt.Errorf("bounds: %d candidates ending in %d, want 1: %x", len(hits), total, hits)
	}
	return hits[0], s.u32s(hits[0], n), nil
}

func (s *Scanner) pathPtr(i int) bool {
	j, ok := s.idx(uint64(s.u32(i)))
	if !ok {
		return false
	}
	for n := 0; n < 260 && j+n < len(s.rd); n++ {
		c := s.rd[j+n]
		if c == 0 {
			return n > 0
		}
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return false
}
func (s *Scanner) FindPaths(known string) (start int, count int, err error) {
	needle := append(append([]byte{0}, known...), 0)
	for from := 0; from < len(s.rd); {
		i := bytes.Index(s.rd[from:], needle)
		if i < 0 {
			break
		}
		i += from
		from = i + 1
		strVA := uint32(s.va(i + 1))
		for j := 0; j+4 <= len(s.rd); j += 4 {
			if s.u32(j) != strVA {
				continue
			}
			st, end := j, j+4
			for st >= 4 && s.pathPtr(st-4) {
				st -= 4
			}
			for end+4 <= len(s.rd) && s.pathPtr(end) {
				end += 4
			}
			return st, (end - st) / 4, nil
		}
	}
	return 0, 0, errors.New("paths: known string or a pointer to it not found")
}

func (s *Scanner) FindOffsets(b []uint32) (int, error) {
	count := int(b[len(b)-1])
	var hits []int
	for i := 0; i+4*count <= len(s.rd); i += 4 {
		at := func(slot uint32) uint32 { return s.u32(i + 4*int(slot)) }
		ok := true
		for a := 0; a+1 < len(b) && ok; a++ {
			lo, hi := b[a], b[a+1]
			if at(lo) != 0 || (hi-lo > 1 && at(lo+1) == 0) {
				ok = false
			}
		}
		for a := 0; a+1 < len(b) && ok; a++ {
			for sl := b[a] + 1; sl < b[a+1]; sl++ {
				if at(sl) < at(sl-1) {
					ok = false
					break
				}
			}
		}
		if ok {
			hits = append(hits, i)
		}
	}
	if len(hits) != 1 {
		return 0, fmt.Errorf("offsets: %d candidates, want 1", len(hits))
	}
	return hits[0], nil
}

func (s *Scanner) FindSizes(b, off []uint32) (int, error) {
	count := len(off)
	isLast := make([]bool, count)
	for a := 1; a < len(b); a++ {
		isLast[b[a]-1] = true
	}
	want := make([]uint32, count)
	for sl := 0; sl < count-1; sl++ {
		if !isLast[sl] {
			want[sl] = off[sl+1] - off[sl]
		}
	}

	var hits []int
	for i := 0; i+4*count <= len(s.rd); i += 4 {
		if s.u32(i) != want[0] {
			continue
		}
		eq, total, ok := 0, 0, true
		for sl := 0; sl < count; sl++ {
			if isLast[sl] {
				continue
			}
			v := s.u32(i + 4*sl)
			if v > want[sl] {
				ok = false
				break
			}
			total++
			if v == want[sl] {
				eq++
			}
		}
		if ok && eq*100 >= total*95 {
			hits = append(hits, i)
		}
	}
	if len(hits) != 1 {
		return 0, fmt.Errorf("sizes: %d candidates, want 1", len(hits))
	}
	return hits[0], nil
}

func (s *Scanner) Locate(keyHead []byte, keySum [32]byte, knownPath string, archives int) (Layout, error) {
	var l Layout
	var err error

	if l.Key, err = s.FindKey(keyHead, keySum); err != nil {
		return l, err
	}

	pi, count, err := s.FindPaths(knownPath)
	if err != nil {
		return l, err
	}
	l.Paths = s.va(pi)

	bi, bounds, err := s.FindBounds(archives+1, uint32(count))
	if err != nil {
		return l, err
	}
	l.Bounds = s.va(bi)

	oi, err := s.FindOffsets(bounds)
	if err != nil {
		return l, err
	}
	l.Offsets = s.va(oi)

	si, err := s.FindSizes(bounds, s.u32s(oi, count))
	if err != nil {
		return l, err
	}
	l.Sizes = s.va(si)

	return l, nil
}
