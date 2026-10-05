package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"rearc-bintool/encryption"
	"rearc-bintool/tables"
)

// Ghidra decomp
var LayoutV145 = tables.Layout{
	Bounds: 0x8CDCF0, Paths: 0x8B8270, Sizes: 0x8A23E8,
	Offsets: 0x8CDDB8, Key: 0x8B7E70,
}

// what we've all been waiting for
func unpackArchive(steamPath, outDir string, t *tables.Tables, a int) error {
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
		plain, err := encryption.Decrypt(buf, t.Key)
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

// non mandatory
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

func packArchive(archivePath, origBin, outBin string, t *tables.Tables, a int) error {
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
		enc, err := encryption.Encrypt(plain, t.Key)
		if err != nil {
			return err
		}

		if _, err := f.WriteAt(enc, int64(t.Offsets[s])); err != nil {
			return fmt.Errorf("write error slot %d: (%s): %w", s, t.Paths[s], err)
		}
	}

	return nil
}

func unpackArchiveAll() {
	cfg, err := OpenConfig("../settings.cfg")
	if err != nil {
		log.Fatal(err)
	}

	steamPath := cfg.Data["steam_path"]

	t, err := tables.NewTables(filepath.Join(steamPath, "MBTL.exe"), LayoutV145)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < tables.Bin_Count; i++ {
		if err := unpackArchive(steamPath, "../unpacked", t, i); err != nil {
			log.Fatal(err)
		}
	}
}

func cmd_unpack_single(num int) {
	if num >= tables.Bin_Count-1 || num < 0 {
		log.Fatal("Unable to unpack bin number, number out of index")
		return
	}
	cfg, err := OpenConfig("../settings.cfg")
	if err != nil {
		log.Fatal(err)
		return
	}
	steamPath := cfg.Data["steam_path"]

	t, err := tables.NewTables(filepath.Join(steamPath, "MBTL.exe"), LayoutV145)
	if err != nil {
		log.Fatal(err)
	}

	unpackArchive(steamPath, "../unpacked", t, num)
}

func main() {
	var test int
	var bin int
	var operation string
	var unpackAll bool

	flag.IntVar(&test, "test", -1, "chooses a test to be ran")
	flag.IntVar(&bin, "bin", 0, "chooses a bin to perform the operation")
	flag.StringVar(&operation, "op", "unpack", "What you would like to do to the bin")
	flag.BoolVar(&unpackAll, "UA", false, "unpacks all bins in the game directory, default is false")

	flag.Parse()

	if unpackAll {
		unpackArchiveAll()
	} else if test != -1 {
		switch test {
		case 1:
			testMain()
		case 2:
			testEquals()
		}
	} else if operation == "unpack" {
		cmd_unpack_single(bin)
	} else if operation == "pack" {
		fmt.Println("Sorry this operation is not yet supported.")
	}
}
