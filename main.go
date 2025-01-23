package main

import (
	"context"
	"bufio"
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

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"
	"gopkg.in/yaml.v3"
)

// Config structure for YAML configuration
type Config struct {
	Region       string   `yaml:"region"`
	Directory    string   `yaml:"directory"`
	Verbose      bool     `yaml:"verbose"`
	Pml          bool     `yaml:"pml"`
	Feedback     bool     `yaml:"feedback"`
	MaxWorkers   int      `yaml:"maxWorkers"`
	ExcludeDir   string   `yaml:"excludeDir"`
	TimeoutLimit int      `yaml:"timeoutLimit"`
	Tags         []string `yaml:"tags"`
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
		FileName    string `json:"fileName"`
		MalwareName string `json:"malwareName"`
	} `json:"foundMalwares"`
	FileSHA1   string `json:"fileSHA1"`
	FileSHA256 string `json:"fileSHA256"`
}

// Variables
var (
	apiKey           = flag.String("apiKey", "", "Vision One API Key. Can also use V1_FS_KEY env var")
	region           = flag.String("region", "us-east-1", "Vision One Region")
	directory        = flag.String("directory", "", "Path to Directory to scan")
	verbose          = flag.Bool("verbose", false, "Log all scans to stdout")
	pml              = flag.Bool("pml", false, "Enable predictive machine learning detection")
	feedback         = flag.Bool("feedback", false, "Enable SPN feedback")
	maxScanWorkers   = flag.Int("maxWorkers", 100, "Max number concurrent file scans Unlimited: -1")
	excludeDirFile   = flag.String("exclude-dir", "", "Path to file containing directories to exclude from the scan")
	timeoutLimit     = flag.Int("timeoutlimit", 10, "Timeout limit in seconds for scanning a file")
	configFile       = flag.String("config", "", "Path to YAML configuration file")

	excludedDirs     map[string]struct{} // Set to store directories to exclude from the scan
	totalScanned     int64
	filesWithMalware int64
	filesClean       int64
	waitGroup        sync.WaitGroup
	mu               sync.Mutex
	scanLog          *os.File
	skippedFilesLog  *os.File
	client           *amaasclient.AmaasClient
	tags             []string
)

func testAuth(client *amaasclient.AmaasClient) error {
	_, err := client.ScanBuffer([]byte(""), "testAuth", nil)
	return err
}

func loadExcludedDirs() error {
	if *excludeDirFile == "" {
		return nil
	}

	file, err := os.Open(*excludeDirFile)
	if err != nil {
		return fmt.Errorf("Error opening exclusion file: %v", err)
	}
	defer file.Close()

	excludedDirs = make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		dir := strings.TrimSpace(scanner.Text())
		if dir != "" {
			excludedDirs[dir] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("Error reading exclusion file: %v", err)
	}

	return nil
}

func loadConfig(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("Error opening config file: %v", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	config := &Config{}
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("Error decoding config file: %v", err)
	}

	return config, nil
}

func main() {
	flag.Parse()

	if *configFile != "" {
		config, err := loadConfig(*configFile)
		if err != nil {
			log.Fatalf("Error loading configuration: %v", err)
		}

		if config.Region != "" {
			*region = config.Region
		}
		if config.Directory != "" {
			*directory = config.Directory
		}
		*verbose = config.Verbose
		*pml = config.Pml
		*feedback = config.Feedback
		*maxScanWorkers = config.MaxWorkers
		if config.ExcludeDir != "" {
			*excludeDirFile = config.ExcludeDir
		}
		if config.TimeoutLimit > 0 {
			*timeoutLimit = config.TimeoutLimit
		}
		tags = config.Tags
	}

	if *apiKey == "" {
		if key, found := os.LookupEnv("V1_FS_KEY"); found {
			*apiKey = key
		} else {
			log.Fatal("API key is required. Use -apiKey or set V1_FS_KEY environment variable.")
		}
	}

	if *directory == "" {
		log.Fatal("Directory to scan is required. Use -directory flag.")
	}

	if err := loadExcludedDirs(); err != nil {
		log.Fatalf("Error loading excluded directories: %v", err)
	}

	var err error
	client, err = amaasclient.NewClient(*apiKey, *region)
	if err != nil {
		log.Fatalf("Error creating Vision One client: %v", err)
	}
	defer client.Destroy()

	if *pml {
		client.SetPMLEnable()
	}
	if *feedback {
		client.SetFeedbackEnable()
	}

	if err := testAuth(client); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	logFileName := time.Now().Format("01-02-2006T15:04")
	scanLog, err = os.OpenFile(fmt.Sprintf("%s-Scan.log", logFileName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Error creating scan log file: %v", err)
	}
	defer scanLog.Close()

	skippedFilesLog, err = os.OpenFile(fmt.Sprintf("%s-skipped_files.log", logFileName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Error creating skipped files log: %v", err)
	}
	defer skippedFilesLog.Close()

	concurrencyLimit := make(chan struct{}, *maxScanWorkers)
	start := time.Now()
	waitGroup.Add(1)
	go scanDirectory(*directory, time.Duration(*timeoutLimit)*time.Second, concurrencyLimit)
	waitGroup.Wait()

	log.Printf("Total scan time: %v", time.Since(start))
}

func scanDirectory(path string, timeout time.Duration, concurrencyLimit chan struct{}) {
	defer waitGroup.Done()

	files, err := os.ReadDir(path)
	if err != nil {
		log.Printf("Error reading directory %s: %v", path, err)
		return
	}

	for _, file := range files {
		fullPath := filepath.Join(path, file.Name())
		if file.IsDir() {
			waitGroup.Add(1)
			go scanDirectory(fullPath, timeout, concurrencyLimit)
		} else {
			waitGroup.Add(1)
			go func(fp string) {
				defer waitGroup.Done()
				concurrencyLimit <- struct{}{}
				if err := scanFile(fp, timeout); err != nil {
					log.Printf("Error scanning file %s: %v", fp, err)
				}
				<-concurrencyLimit
			}(fullPath)
		}
	}
}

func scanFile(filePath string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	scanErrChan := make(chan error, 1)
	go func() {
		_, err := client.ScanFile(filePath, tags)
		scanErrChan <- err
	}()

	select {
	case <-ctx.Done():
		logSkippedFile(filePath,
