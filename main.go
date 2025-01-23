package main

import (
	"context"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

// Config struct for YAML configuration
type Config struct {
	Region          string   `yaml:"region"`
	Directory       string   `yaml:"directory"`
	Verbose         bool     `yaml:"verbose"`
	PML             bool     `yaml:"pml"`
	Feedback        bool     `yaml:"feedback"`
	MaxScanWorkers  int      `yaml:"maxWorkers"`
	InternalAddress string   `yaml:"internalAddress"`
	InternalTLS     bool     `yaml:"internalTLS"`
	ExcludeDirFile  string   `yaml:"excludeDir"`
	TimeoutLimit    int      `yaml:"timeoutLimit"`
	Tags            []string `yaml:"tags"`
}

// Struct for Tags
type Tags []string

func (tags *Tags) String() string {
	return fmt.Sprintf("%v", *tags)
}

func (tags *Tags) Set(value string) error {
	*tags = append(*tags, strings.Split(value, ",")...)
	if len(*tags) > 8 {
		log.Fatalf("tags accepts up to 8 strings")
	}
	return nil
}

// Global Variables
var (
	apiKey           = flag.String("apiKey", "", "Vision One API Key. Can also use V1_FS_KEY env var")
	configFile       = flag.String("config", "config.yaml", "Path to YAML configuration file")
	region           string
	directory        string
	verbose          bool
	pml              bool
	feedback         bool
	maxScanWorkers   int
	internalAddress  string
	internalTLS      bool
	excludeDirFile   string
	timeoutLimit     int
	tags             Tags
	excludedDirs     map[string]struct{}
	totalScanned     int64
	filesWithMalware int64
	filesClean       int64
	waitGroup        sync.WaitGroup
	client           *amaasclient.AmaasClient
	scanLog          *os.File
	skippedFilesLog  *os.File
	mu               sync.Mutex
)

// LoadConfig loads the YAML configuration file
func LoadConfig(configFile string) (*Config, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("error opening config file: %v", err)
	}
	defer file.Close()

	var config Config
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %v", err)
	}

	return &config, nil
}

// OverrideConfigWithFlags overrides YAML config with command-line flags
func OverrideConfigWithFlags(config *Config) {
	if *region != "" {
		config.Region = *region
	}
	if *directory != "" {
		config.Directory = *directory
	}
	if *verbose {
		config.Verbose = *verbose
	}
	if *pml {
		config.PML = *pml
	}
	if *feedback {
		config.Feedback = *feedback
	}
	if *maxScanWorkers != 0 {
		config.MaxScanWorkers = *maxScanWorkers
	}
	if *internalAddress != "" {
		config.InternalAddress = *internalAddress
	}
	if !*internalTLS {
		config.InternalTLS = *internalTLS
	}
	if *excludeDirFile != "" {
		config.ExcludeDirFile = *excludeDirFile
	}
	if *timeoutLimit != 0 {
		config.TimeoutLimit = *timeoutLimit
	}
}

// Main Function
func main() {
	flag.Var(&tags, "tags", "Comma-separated tags (up to 8 strings)")
	flag.Parse()

	// Load YAML configuration
	config, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Override YAML config with command-line flags
	OverrideConfigWithFlags(config)

	// Assign configuration values to variables
	region = config.Region
	directory = config.Directory
	verbose = config.Verbose
	pml = config.PML
	feedback = config.Feedback
	maxScanWorkers = config.MaxScanWorkers
	internalAddress = config.InternalAddress
	internalTLS = config.InternalTLS
	excludeDirFile = config.ExcludeDirFile
	timeoutLimit = config.TimeoutLimit
	tags = config.Tags

	if verbose {
		fmt.Printf("Effective Configuration: %+v\n", config)
	}

	// Initialize logging
	timestamp := time.Now().Format("01-02-2006T15:04")
	LOG_FILE := fmt.Sprintf("%s.error.log", timestamp)
	logFile, err := os.OpenFile(LOG_FILE, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Panic(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	// Initialize scan log file
	scanLogFile := fmt.Sprintf("%s-Scan.log", timestamp)
	scanLog, err = os.OpenFile(scanLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error creating scan log file: %v", err)
	}
	defer scanLog.Close()

	// Initialize channel for file scan concurrency
	var scanFileChannel chan struct{}

	if maxScanWorkers == -1 {
		scanFileChannel = make(chan struct{})
	} else {
		scanFileChannel = make(chan struct{}, maxScanWorkers)
	}

	// Start scanning the initial directory
	startTime := time.Now()
	waitGroup.Add(1)
	go scanDirectory(client, directory, scanFileChannel, time.Duration(timeoutLimit)*time.Second)

	// Wait for all goroutines to finish before exiting
	waitGroup.Wait()

	// Calculate total scan time
	timeTaken := time.Since(startTime)

	// Write scan statistics to log
	mu.Lock()
	fmt.Fprintf(scanLog, "Total Scan Time: %s\nTotal Files Scanned: %d\nFiles with Malware: %d\nFiles Clean: %d\n",
		timeTaken, atomic.LoadInt64(&totalScanned), atomic.LoadInt64(&filesWithMalware), atomic.LoadInt64(&filesClean))
	mu.Unlock()

	// Output the summary to the terminal
	fmt.Println("\n--- Scan Summary ---")
	fmt.Printf("Total Files Scanned: %d\n", atomic.LoadInt64(&totalScanned))
	fmt.Printf("Files with Malware: %d\n", atomic.LoadInt64(&filesWithMalware))
	fmt.Printf("Files Clean: %d\n", atomic.LoadInt64(&filesClean))
	fmt.Printf("Total Scan Time: %s\n", timeTaken)
}

// Function to recursively scan a directory
func scanDirectory(client *amaasclient.AmaasClient, directory string, scanFileChannel chan struct{}, timeout time.Duration) {
	defer waitGroup.Done()

	// Normalize the directory path
	normalizedDir := filepath.Clean(directory)

	// Check for exclusions
	for excludedDir := range excludedDirs {
		if strings.HasPrefix(normalizedDir, excludedDir) {
			if verbose {
				log.Printf("Skipping excluded directory: %s\n", directory)
			}
			return
		}
	}

	// Process files and directories
	files, err := os.ReadDir(directory)
	if err != nil {
		if verbose {
			log.Printf("Error reading directory: %v\n", err)
		}
		return
	}

	for _, file := range files {
		fp := filepath.Join(directory, file.Name())
		if file.IsDir() {
			waitGroup.Add(1)
			go scanDirectory(client, fp, scanFileChannel, timeout)
		} else {
			waitGroup.Add(1)
			go func(filePath string) {
				scanFileChannel <- struct{}{}
				if err := scanFile(client, filePath, timeout); err != nil && verbose {
					log.Printf("Error scanning file %s: %v\n", filePath, err)
				}
				<-scanFileChannel
				waitGroup.Done()
			}(fp)
		}
	}
}

// Function to scan a file
func scanFile(client *amaasclient.AmaasClient, filePath string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()

	rawResult, err := client.ScanFile(filePath, tags)
	if err != nil {
		log.Printf("Error scanning file %s: %v\n", filePath, err)
		return err
	}

	var result ScanResult
	if err := json.Unmarshal([]byte(rawResult), &result); err != nil {
		log.Printf("Error unmarshaling result: %v\n", err)
		return err
	}

	// Log results
	mu.Lock()
	fmt.Fprintf(scanLog, "Scanned: %s in %v\n", filePath, time.Since(start))
	mu.Unlock()

	return nil
}
