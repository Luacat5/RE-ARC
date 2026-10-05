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

	"testing"
)

var binNum = 14

func TestRoundTrip(test *testing.T) {
	cfg, err := OpenConfig("../settings.cfg")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Beginning extract repack roundtrip test")

	t, steamPath, _, err := GetTables(cfg)

	if err != nil {
		test.Error(err)
	}

	binName := fmt.Sprintf("data%03d.bin", binNum)
	outDir := fmt.Sprintf("../output/%s", binName)

	if err := unpackArchive(*steamPath, "../unpacked", t, binNum); err != nil {
		test.Error(err)
	}

	if err := packArchive("../unpacked", filepath.Join(*steamPath, binName), outDir, t, binNum); err != nil {
		test.Error(err)
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
func TestEquals(test *testing.T) {
	cfg, err := OpenConfig("../settings.cfg")
	if err != nil {
		test.Error(err)
	}
	binName := fmt.Sprintf("data%03d.bin", binNum)
	result, err := sameFile(path.Join(cfg.Data["steam_path"], binName), path.Join("../output", binName))
	if err != nil {
		test.Error(err)
	}
	fmt.Printf("File match: %t\n", result)
}
