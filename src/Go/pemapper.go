package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

type PEMapper struct {
	file      *os.File
	pe        *pe.File
	ImageBase uint64
}

func NewPEMapper(path string) (*PEMapper, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	peFile, err := pe.NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}

	var imageBase uint64
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		f.Close()
		return nil, fmt.Errorf("unsupported or missing optional header")
	}

	return &PEMapper{
		file:      f,
		pe:        peFile,
		ImageBase: imageBase,
	}, nil
}

func (m *PEMapper) Close() {
	m.file.Close()
}

// PrintSections displays all sections (.text, .rdata, etc.) and their RVA ranges
func (m *PEMapper) PrintSections() {
	fmt.Printf("Image Base: 0x%X\n\n", m.ImageBase)
	fmt.Printf("%-10s %-12s %-12s %-12s\n", "Name", "RVA Start", "RVA End", "Disk Offset")
	fmt.Println("--------------------------------------------------")

	for _, sec := range m.pe.Sections {
		startRVA := sec.VirtualAddress
		endRVA := sec.VirtualAddress + sec.VirtualSize
		fmt.Printf("%-10s 0x%08X   0x%08X   0x%08X\n", sec.Name, startRVA, endRVA, sec.Offset)
	}
}

func (m *PEMapper) VAToOffset(va uint64) (int64, error) {
	if va < m.ImageBase {
		return 0, fmt.Errorf("VA 0x%X is below Image Base 0x%X", va, m.ImageBase)
	}
	rva := uint32(va - m.ImageBase)

	for _, sec := range m.pe.Sections {
		// Check if RVA falls inside this section's virtual memory bounds
		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.Size {
			fileOffset := int64(rva - sec.VirtualAddress + sec.Offset)
			return fileOffset, nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%X does not map to any file section", rva)
}

func (m *PEMapper) ReadBytesAtVA(va uint64, length int) ([]byte, error) {
	offset, err := m.VAToOffset(va)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, length)
	_, err = m.file.ReadAt(buf, offset)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (m *PEMapper) ReadU32s(va uint64, n int) ([]uint32, error) {
	b, err := m.ReadBytesAtVA(va, n*4)
	if err != nil {
		return nil, err
	}
	out := make([]uint32, n)
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(b[i*4:])
	}
	return out, nil
}

func (m *PEMapper) ReadCString(va uint64) (string, error) {
	var acc []byte
	buf := make([]byte, 256)
	for len(acc) < 4096 {
		off, err := m.VAToOffset(va)
		if err != nil {
			return "", err
		}
		n, err := m.file.ReadAt(buf, off)
		if n == 0 && err != nil {
			return "", err
		}
		if i := bytes.IndexByte(buf[:n], 0); i >= 0 {
			return string(append(acc, buf[:i]...)), nil
		}
		acc = append(acc, buf[:n]...)
		va += uint64(n)
	}
	return "", fmt.Errorf("unterminated string near VA 0x%X", va)
}
