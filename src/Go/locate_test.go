package main

import (
	"fmt"
	"rearc-bintool/tables"
	"strconv"
	"testing"
)

// true as of 10/5/2026@4:40pm
var LayoutV145 = tables.Layout{
	Bounds: 0x8CDCF0, Paths: 0x8B8270, Sizes: 0x8A23E8,
	Offsets: 0x8CDDB8, Key: 0x8B7E70,
}

func TestKeySumHead(t *testing.T) {
	cfg, err := OpenConfig("../settings.cfg")

	if err != nil {
		t.Error(err)
	}
	steamPath := cfg.Data["steam_path"]
	head, sum, err := tables.FindKeyCache(LayoutV145, steamPath, 21)

	fmt.Printf("head: %x\n", head)
	fmt.Printf("sum:  %x\n", sum)
}

func TestLocateV145(t *testing.T) {
	cfg, err := OpenConfig("../settings.cfg")

	if err != nil {
		t.Error(err)
	}
	steamPath := cfg.Data["steam_path"]
	searchString := cfg.Data["search_string"]
	binCount, err := strconv.Atoi(cfg.Data["binfile_count"])
	if err != nil {
		t.Fatal(err)
	}

	layout, err := tables.LayoutForMBTL(steamPath, searchString, binCount)
	if err != nil {
		t.Fatal(err)
	}

	if layout.Bounds != LayoutV145.Bounds || layout.Key != LayoutV145.Key ||
		layout.Offsets != LayoutV145.Offsets || layout.Sizes != LayoutV145.Sizes || layout.Paths != LayoutV145.Paths {
		t.Errorf("Failure to match layouts! Bounds: %x, Paths: %x, Sizes:%x, Offsets: %x, Key: %x", layout.Bounds, layout.Paths, layout.Sizes, layout.Offsets, layout.Key)
	}
}
