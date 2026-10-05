package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"

	"rearc-bintool/tables"
)

var binNum = 7

func testMain() {
	cfg, err := OpenConfig("../settings.cfg")
	if err != nil {
		log.Fatal(err)
	}

	steamPath := cfg.Data["steam_path"]

	fmt.Println("Beginning extract repack roundtrip test")

	t, err := tables.NewTables(filepath.Join(steamPath, "MBTL.exe"), LayoutV145)

	if err != nil {
		log.Fatal(err)
	}

	binName := fmt.Sprintf("data%03d.bin", binNum)
	outDir := fmt.Sprintf("../output/%s", binName)

	if err := unpackArchive(steamPath, "../unpacked", t, binNum); err != nil {
		log.Fatal(err)
	}

	if err := packArchive("../unpacked", filepath.Join(steamPath, binName), outDir, t, binNum); err != nil {
		log.Fatal(err)
	}
}

func sameFile(a, b string) (bool, error) {
	ha, err := hashFile(a)
	if err != nil {
		return false, err
	}
	hb, err := hashFile(b)
	if err != nil {
		return false, err
	}
	return ha == hb, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func testEquals() {
	cfg, err := OpenConfig("../settings.cfg")
	if err != nil {
		log.Fatal(err)
	}
	binName := fmt.Sprintf("data%03d.bin", binNum)
	result, err := sameFile(path.Join(cfg.Data["steam_path"], binName), path.Join("../output", binName))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("File match: %t\n", result)
}
