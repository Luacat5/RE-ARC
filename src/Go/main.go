package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"rearc-bintool/encryption"
	"rearc-bintool/tables"
)

type SessionInformation struct {
	stagingDir *string
	outDir     *string

	originalBin *string
	exportBin   *string

	cfg *ReArcConfig

	binNumber int
}

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

func packArchive(archivePath, origBin, outBin string, t *tables.Tables, a int) error {
	f, err := os.OpenFile(outBin, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
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

// boilerplate
func GetTables(cfg *ReArcConfig) (*tables.Tables, *string, *int, error) {
	if cfg == nil {
		return nil, nil, nil, fmt.Errorf("Error: Missing config file")
	}
	steamPath := cfg.Data["steam_path"]
	searchString := cfg.Data["search_string"]
	binCount, _ := strconv.Atoi(cfg.Data["binfile_count"])

	l, err := tables.LayoutForMBTL(steamPath, searchString, binCount)
	if err != nil {
		return nil, nil, nil, err
	}

	t, err := tables.NewTables(filepath.Join(steamPath, "MBTL.exe"), *l, binCount)
	if err != nil {
		return nil, nil, nil, err
	}

	return t, &steamPath, &binCount, nil
}

func unpackArchiveAll(cfg *ReArcConfig) {
	t, steamPath, binCount, err := GetTables(cfg)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < *binCount; i++ {
		if err := unpackArchive(*steamPath, "../unpacked", t, i); err != nil {
			log.Fatal(err)
		}
	}
}

func cmd_unpack_single(cfg *ReArcConfig, session SessionInformation) {
	t, steamPath, _, err := GetTables(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := unpackArchive(*steamPath, "../unpacked", t, session.binNumber); err != nil {
		log.Fatal(err)
	}
}

func cmd_pack_single(cfg *ReArcConfig, session SessionInformation) {
	if *session.stagingDir == "" {
		log.Fatal("No staging folder specified, try using -fp flag")
	}
	cfg, err := OpenConfig("../settings.cfg")
	if err != nil {
		log.Fatal(err)
	}

	t, _, _, err := GetTables(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := packArchive(*session.stagingDir, *session.originalBin, *session.exportBin, t, session.binNumber); err != nil {
		log.Fatal(err)
	}
}

func main() {
	var bin int
	var operation string
	var unpackAll bool
	var stagingFolderPath string

	outFolderPath := "../output" // fixed for now, flag unneccessary.

	flag.IntVar(&bin, "bin", 0, "chooses a bin by number to perform the operation")
	flag.StringVar(&operation, "op", "unpack", "Specify operation to perform on the bin")
	flag.StringVar(&stagingFolderPath, "fp", "", "Specify staging folder")
	flag.BoolVar(&unpackAll, "all", false, "unpacks all bins in the game directory, overrides all other commands.")

	flag.Parse()

	cfg, err := OpenConfig("../settings.cfg")
	if err != nil {
		log.Fatal(err)
	}

	origBin := filepath.Join(cfg.Data["steamPath"], fmt.Sprintf("data%03d.bin", bin))
	binName := filepath.Base(origBin)
	outBin := filepath.Join("../output/", binName)

	entry := SessionInformation{
		binNumber: bin,

		stagingDir: &stagingFolderPath,
		outDir:     &outFolderPath,

		originalBin: &origBin,
		exportBin:   &outBin,
	}

	if unpackAll {
		switch operation {
		case "pack":
			fmt.Println("Sorry this action is not yet available.")
		case "unpack":
			unpackArchiveAll(cfg)
		}
	} else if operation == "unpack" {
		cmd_unpack_single(cfg, entry)
	} else if operation == "pack" {
		cmd_pack_single(cfg, entry)
	}
}
