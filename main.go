package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"bufio"
	"gopkg.in/yaml.v3"

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

// Config represents the YAML configuration structure
type Config struct {
	Region         string   `yaml:"region"`
	Directory      string   `yaml:"directory"`
	Verbose        bool     `yaml:"verbose"`
	PML            bool     `yaml:"pml"`
	Feedback       bool     `yaml:"feedback"`
	MaxWorkers     int      `yaml:"maxWorkers"`
	ExcludeDirFile string   `yaml:"excludeDirFile"`
	TimeoutLimit   int      `yaml:"timeoutLimit"`
	Tags           []string `yaml:"tags"`
}

// ScanResult represents the structure of a scan result
type ScanResult struct {
	ScannerVersion string `json:"scannerVersion"`
	SchemaVersion  string `json:"schemaVersion"`
	ScanResult     int    `json:"scanResult"`
	ScanId         string `json:"scanId"`
	ScanTimestamp  string `json:"scanTimestamp"`
	FileName       string `json:"fileName"`
	FoundMalwares  []struct {
		FileName   string `json:"fileName"`
		MalwareName string `json:"malwareName"`
	} `json:"foundMalwares"`
	FileSHA1   string `json:"fileSHA1"`
	FileSHA256 string `json:"fileSHA256"`
}

// Variables
var (
	apiKey           = flag.String("apiKey", "", "Vision One API Key. Can also use V1_FS_KEY env var")
	configFile       = flag.String("config", "", "Path to YAML configuration file")
	excludedDirs     map[string]struct{} // Set to store directories to exclude from the scan
	totalScanned     int64
	filesWithMalware int64
	filesClean       int64
	waitGroup        sync.WaitGroup
	client           *amaasclient.AmaasClient
	scanLog          *os.File // File to log scanned files and results
	mu               sync.Mutex
)

func loadConfig(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	config := &Config{}
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %v", err)
	}
	return config, nil
}

func testAuth(client *amaasclient.AmaasClient) error {
	_, err := client.ScanBuffer([]byte(""), "testAuth", nil)
	return err
}

func loadExcludedDirs(filePath string) error {
	excludedDirs = make(map[string]struct{})
	if filePath == "" {
		return nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening exclude directory file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		dir := strings.TrimSpace(scanner.Text())
		if dir != "" {
			excludedDirs[dir] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading exclude directory file: %v", err)
	}
	return nil
}

func scanDirectory(directory string, timeout time.Duration, tags []string) {
	defer waitGroup.Done()

	// Check if directory is excluded
	normalizedDir := filepath.Clean(directory)
	for excludedDir := range excludedDirs {
		if strings.HasPrefix(normalizedDir, excludedDir) {
			log.Printf("Skipping excluded directory: %s\n", directory)
			return
		}
	}

	files, err := os.ReadDir(directory)
	if err != nil {
		log.Printf("Failed to read directory %s: %v", directory, err)
		return
	}

	for _, file := range files {
		filePath := filepath.Join(directory, file.Name())
		if file.IsDir() {
			waitGroup.Add(1)
			go scanDirectory(filePath, timeout, tags)
		} else {
			waitGroup.Add(1)
			go func(path string) {
				defer waitGroup.Done()
				scanFile(path, timeout, tags)
			}(filePath)
		}
	}
}

func scanFile(filePath string, timeout time.Duration, tags []string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rawResult, err := client.ScanFile(filePath, tags)
	if err != nil {
		log.Printf("Error scanning file %s: %v", filePath, err)
		return
	}

	var result ScanResult
	if err := json.Unmarshal([]byte(rawResult), &result); err != nil {
		log.Printf("Error parsing scan result for file %s: %v", filePath, err)
		return
	}

	atomic.AddInt64(&totalScanned, 1)

	if len(result.FoundMalwares) > 0 {
		atomic.AddInt64(&filesWithMalware, 1)
		log.Printf("Malware found in file %s: %+v", filePath, result.FoundMalwares)
	} else {
		atomic.AddInt64(&filesClean, 1)
		log.Printf("File clean: %s", filePath)
	}
}

func main() {
	flag.Parse()

	if *apiKey == "" {
		log.Fatal("API Key is required. Use the -apiKey flag or set the V1_FS_KEY environment variable.")
	}

	if *configFile == "" {
		log.Fatal("Configuration file is required. Use the -config flag to specify the path to the YAML file.")
	}

	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Load exclusion directories
	if err := loadExcludedDirs(config.ExcludeDirFile); err != nil {
		log.Fatalf("Error loading exclusion directories: %v", err)
	}

	// Initialize Vision One client
	client, err = amaasclient.NewClient(*apiKey, config.Region)
	if err != nil {
		log.Fatalf("Error creating Vision One client: %v", err)
	}
	defer client.Destroy()

	if config.PML {
		client.SetPMLEnable()
	}
	if config.Feedback {
		client.SetFeedbackEnable()
	}

	authTest := testAuth(client)
	if authTest != nil {
		log.Fatalf("Authentication failed: %v", authTest)
	}

	// Initialize logs
	timestamp := time.Now().Format("01-02-2006T15:04")
	scanLogFile := fmt.Sprintf("%s-Scan.log", timestamp)
	scanLog, err = os.OpenFile(scanLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error creating scan log file: %v", err)
	}
	defer scanLog.Close()

	startTime := time.Now()
	waitGroup.Add(1)
	go scanDirectory(config.Directory, time.Duration(config.TimeoutLimit)*time.Second, config.Tags)
	waitGroup.Wait()

	log.Printf("Total time: %s", time.Since(startTime))
	log.Printf("Total scanned: %d", totalScanned)
	log.Printf("Files with malware: %d", filesWithMalware)
	log.Printf("Files clean: %d", filesClean)
}
