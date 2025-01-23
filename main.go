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

// Struct to represent the scan result
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
	scanLog         *os.File // File to log scanned files and results
	skippedFilesLog  *os.File // File to log skipped files
	mu              sync.Mutex
)

func testAuth(client *amaasclient.AmaasClient) error {
	_, err := client.ScanBuffer([]byte(""), "testAuth", nil)
	return err
}

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

	// Initialize logs
	timestamp := time.Now().Format("01-02-2006T15:04")
	scanLogFile := fmt.Sprintf("%s-Scan.log", timestamp)
	scanLog, err = os.OpenFile(scanLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error creating scan log file: %v", err)
	}
	defer scanLog.Close()

	skipLogFile := fmt.Sprintf("%s-skipped_files.log", timestamp)
	skippedFilesLog, err = os.OpenFile(skipLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error creating skipped files log: %v", err)
	}
	defer skippedFilesLog.Close()

	// Initialize Vision One client
	client, err = amaasclient.NewClient(*apiKey, config.Region)
	if err != nil {
		log.Fatalf("Error creating Vision One client: %v", err)
	}
	defer client.Destroy()

	authTest := testAuth(client)
	if authTest != nil {
		log.Fatalf("Authentication failed: %v", authTest)
	}

	// Load exclusion directories
	excludedDirs = make(map[string]struct{})
	if config.ExcludeDirFile != "" {
		file, err := os.Open(config.ExcludeDirFile)
		if err != nil {
			log.Fatalf("Error opening exclude directory file: %v", err)
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
			log.Fatalf("Error reading exclude directory file: %v", err)
		}
	}

	// Start scanning
	startTime := time.Now()
	waitGroup.Add(1)
	go scanDirectory(config.Directory, time.Duration(config.TimeoutLimit)*time.Second, config.MaxWorkers)
	waitGroup.Wait()

	// Log results
	totalTime := time.Since(startTime)
	log.Printf("Total time: %s\n", totalTime)
	log.Printf("Total scanned: %d\n", totalScanned)
	log.Printf("Files with malware: %d\n", filesWithMalware)
	log.Printf("Files clean: %d\n", filesClean)
}

func scanDirectory(directory string, timeout time.Duration, maxWorkers int) {
	defer waitGroup.Done()

	files, err := os.ReadDir(directory)
	if err != nil {
		log.Printf("Failed to read directory %s: %v", directory, err)
		return
	}

	for _, file := range files {
		filePath := filepath.Join(directory, file.Name())
		if file.IsDir() {
			waitGroup.Add(1)
			go scanDirectory(filePath, timeout, maxWorkers)
		} else {
			waitGroup.Add(1)
			go func(path string) {
				defer waitGroup.Done()
				scanFile(path, timeout)
			}(filePath)
		}
	}
}

func scanFile(filePath string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		// Simulate scanning logic
		// Replace with actual SDK call
		time.Sleep(1 * time.Second) // Simulated delay
		errChan <- nil
	}()

	select {
	case <-ctx.Done():
		log.Printf("File scan timed out: %s", filePath)
		logSkippedFile(filePath, "timeout")
	case err := <-errChan:
		if err != nil {
			log.Printf("Error scanning file %s: %v", filePath, err)
			logSkippedFile(filePath, err.Error())
		} else {
			atomic.AddInt64(&totalScanned, 1)
		}
	}
}

func logSkippedFile(filePath, reason string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintf(skippedFilesLog, "Skipped: %s, Reason: %s\n", filePath, reason)
}
