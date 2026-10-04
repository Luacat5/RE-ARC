package main

import (
	"bufio"
	"log"
	"os"
	"strings"
)


type ReArcConfig struct {
	Data map[string]string
} 

// basic config reader

func OpenConfig(filepath string) ReArcConfig{
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatalf("failed to open file: %v", err)
	}
	defer file.Close()

	config_data := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			config_data[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("error reading file: %v", err)
	}

	var new_config ReArcConfig
	new_config.Data = config_data
	return new_config
	
}
