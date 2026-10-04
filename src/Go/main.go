package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

var ActiveConfig = OpenConfig("../settings.cfg")

// Ghidra decomp
var LayoutV145 = Layout{
	Bounds: 0x8CDCF0, Paths: 0x8B8270, Sizes: 0x8A23E8,
	Offsets: 0x8CDDB8, Key: 0x8B7E70,
}

const bin_count = 21

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

func (m *PEMapper) ErrorHandleMBTL(l Layout) (*Tables, error) {
	t := &Tables{}
	var err error

	// error checks
	if t.Bounds, err = m.ReadU32s(l.Bounds, bin_count+1); err != nil {
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

	count := int(t.Bounds[bin_count])

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

	if t.Key, err = m.ReadBytesAtVA(l.Key, table_size); err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	return t, nil
}

// what we've all been waiting for
func unpackArchive(steamPath, outDir string, t *Tables, a int) error {
	f, err := os.Open(filepath.Join(steamPath, fmt.Sprintf("data%03d.bin", a)))
	if err != nil {
		return err
	}
	defer f.Close()

	for s := int(t.Bounds[a]); s < int(t.Bounds[a+1]); s++ {
		buf := make([]byte, t.Sizes[s])
		if _, err := f.ReadAt(buf, int64(t.Offsets[s])); err != nil {
			return fmt.Errorf("slot %d (%s): %w", s, t.Paths[s], err)
		}
		plain, err := Decrypt(buf, t.Key)
		if err != nil {
			return err
		}
		out := filepath.Join(outDir, filepath.FromSlash(t.Paths[s]))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(out, plain, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func packArchive(archivePath, origBin, outBin string, t *Tables, a int) error {
	if err := copyFile(origBin, outBin); err != nil {
		return err
	}
	f, err := os.OpenFile(outBin, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	for s := int(t.Bounds[a]); s < int(t.Bounds[a+1]); s++ {
		src := filepath.Join(archivePath, filepath.FromSlash(t.Paths[s]))
		plain, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if uint32(len(plain)) != t.Sizes[s] {
			return fmt.Errorf("slot %d (%s): size mismatch %d with expected %d", s, t.Paths[s], len(plain), t.Sizes[s])
		}
		enc, err := Encrypt(plain, t.Key)
		if err != nil {
			return err
		}

		if _, err := f.WriteAt(enc, int64(t.Offsets[s])); err != nil {
			return fmt.Errorf("write error slot %d: (%s): %w", s, t.Paths[s], err)
		}
	}

	return nil
}

var cfg = OpenConfig("../settings.cfg")
var steamPath = cfg.Data["steam_path"]

// single bin unpack
func testMain() {
	fmt.Println("Beginning extract repack roundtrip test")

	m, err := NewPEMapper(filepath.Join(steamPath, "MBTL.exe"))
	if err != nil {
		log.Fatal(err)
	}
	defer m.Close()

	t, err := m.ErrorHandleMBTL(LayoutV145)
	if err != nil {
		log.Fatal(err)
	}

	binNum := 7
	binName := fmt.Sprintf("data%03d.bin", binNum)
	outDir := fmt.Sprintf("../output/%s", binName)

	if err := unpackArchive(steamPath, "../unpacked", t, binNum); err != nil {
		log.Fatal(err)
	}

	if err := packArchive("../unpacked", filepath.Join(steamPath, binName), outDir, t, binNum); err != nil {
		log.Fatal(err)
	}
}

func main() {
	// testMain()
	m, err := NewPEMapper(filepath.Join(steamPath, "MBTL.exe"))
	if err != nil {
		log.Fatal(err)
	}
	defer m.Close()

	t, err := m.ErrorHandleMBTL(LayoutV145)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < bin_count; i++ {
		if err := unpackArchive(steamPath, "../unpacked", t, i); err != nil {
			log.Fatal(err)
		}
	}
}
