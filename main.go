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
)

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

// Function to build the config file, then when calling main ask items missing
type Tags []string

// Returns the string representation of Tags
func (tags *Tags) String() string {
	return fmt.Sprintf("%v", *tags)
}

// Set the value of Tags
func (tags *Tags) Set(value string) error {
	*tags = append(*tags, strings.Split(value, ",")...)
	if len(*tags) > 8 {
		log.Fatalf("tags accepts up to 8 strings")
	}
	return nil
}

// Variables
var (
	apiKey           = flag.String("apiKey", "", "Vision One API Key. Can also use V1_FS_KEY env var")
	region           = flag.String("region", "us-east-1", "Vision One Region")
	directory        = flag.String("directory", "", "Path to Directory to scan")
	verbose          = flag.Bool("verbose", false, "Log all scans to stdout")
	pml              = flag.Bool("pml", false, "Enable predictive machine learning detection")
	feedback         = flag.Bool("feedback", false, "Enable SPN feedback")
	digest           = flag.Bool("digest", true, "Enable or disable digest calculation")
	maxScanWorkers   = flag.Int("maxWorkers", 100, "Max number concurrent file scans. Unlimited: -1")
	internal_address = flag.String("internal_address", "", "Internal Service Gateway Address")
	internal_tls     = flag.Bool("internal_tls", true, "Use TLS for internal Service Gateway")
	excludeDirFile   = flag.String("exclude-dir", "", "Path to file containing directories to exclude from the scan")
	timeoutLimit     = flag.Int("timeoutlimit", 10, "Timeout limit in seconds for scanning a file")
	excludedDirs     map[string]struct{}
	totalScanned     int64
	filesWithMalware int64
	filesClean       int64
	waitGroup        sync.WaitGroup
	tags             Tags
	client           *amaasclient.AmaasClient
	mu               sync.Mutex
	scanLog          *os.File
)

func testAuth(client *amaasclient.AmaasClient) error {
	_, err := client.ScanBuffer([]byte(""), "testAuth", nil)
	if err != nil {
		return err
	}
	return nil
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

func main() {
	// Parse command-line flags
	flag.Var(&tags, "tags", "Up to 8 strings separated by commas")
	flag.Parse()

	var v1ApiKey string

	// Check for required arguments
	k, e := os.LookupEnv("V1_FS_KEY")
	if e {
		v1ApiKey = k
	} else {
		if *apiKey == "" {
			flag.PrintDefaults()
			log.Fatal("Use V1_FS_KEY env var or -apiKey parameter")
		} else {
			v1ApiKey = *apiKey
		}
	}

	if *directory == "" {
		flag.PrintDefaults()
		log.Fatal("Missing required argument: -directory")
	}

	// Load exclusion directories if provided
	if err := loadExcludedDirs(); err != nil {
		log.Fatalf("Error loading exclusion directories: %v", err)
	}

	// Create Vision One client
	var err error
	if *internal_address != "" {
		client, err = amaasclient.NewClientInternal(v1ApiKey, *internal_address, *internal_tls)
		if err != nil {
			log.Fatalf("Error creating client: %v", err)
		}
	} else {
		client, err = amaasclient.NewClient(v1ApiKey, *region)
		if err != nil {
			log.Fatalf("Error creating client: %v", err)
		}
	}

	// Handle digest flag
	if *digest {
		log.Println("Digest calculation is enabled.")
	} else {
		log.Println("Digest calculation is disabled.")
	}

	// Enable or disable PML and feedback based on flags
	if *pml {
		client.SetPMLEnable()
		if *verbose {
			log.Println("PML is enabled.")
		}
	} else if *verbose {
		log.Println("PML is disabled.")
	}

	if *feedback {
		client.SetFeedbackEnable()
		if *verbose {
			log.Println("Feedback is enabled.")
		}
	} else if *verbose {
		log.Println("Feedback is disabled.")
	}

	// Test authentication
	authTest := testAuth(client)
	if authTest != nil {
		fmt.Println("Bad Credentials. Check API KEY and role permissions")
		os.Exit(1)
	}

defer client.Destroy()

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

	// Initialize the scan log file
	scanLogFile := fmt.Sprintf("%s-Scan.log", timestamp)
	scanLog, err = os.OpenFile(scanLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error creating scan log file: %v", err)
	}
	defer scanLog.Close()

	// Initialize channel for file scan concurrency control
	var scanFileChannel chan struct{}
	if *maxScanWorkers == -1 {
		scanFileChannel = make(chan struct{})
	} else {
		scanFileChannel = make(chan struct{}, *maxScanWorkers)
	}

	// Start scanning the initial directory
	startTime := time.Now()
	waitGroup.Add(1)
	go scanDirectory(client, *directory, scanFileChannel, time.Duration(*timeoutLimit)*time.Second)

	// Wait for all goroutines to finish
	waitGroup.Wait()

	// Calculate total scan time
	timeTaken := time.Since(startTime)

	// Write scan statistics
	mu.Lock()
	fmt.Fprintf(scanLog, "Total Scan Time: %s\nTotal Files Scanned: %d\nFiles with Malware: %d\nFiles Clean: %d\n", timeTaken, atomic.LoadInt64(&totalScanned), atomic.LoadInt64(&filesWithMalware), atomic.LoadInt64(&filesClean))
	mu.Unlock()

	// Output the summary
	fmt.Println("\n--- Scan Summary ---")
	fmt.Printf("Total Files Scanned: %d\n", atomic.LoadInt64(&totalScanned))
	fmt.Printf("Files with Malware: %d\n", atomic.LoadInt64(&filesWithMalware))
	fmt.Printf("Files Clean: %d\n", atomic.LoadInt64(&filesClean))
	fmt.Printf("Total Scan Time: %s\n", timeTaken)
}

func scanDirectory(client *amaasclient.AmaasClient, directory string, scanFileChannel chan struct{}, timeout time.Duration) {
	defer waitGroup.Done()
	normalizedDir := filepath.Clean(directory)
	for excludedDir := range excludedDirs {
		if strings.HasPrefix(normalizedDir, filepath.Clean(excludedDir)) {
			if *verbose {
				log.Printf("Skipping excluded directory: %s\n", directory)
			}
			return
		}
	}

	files, err := os.ReadDir(directory)
	if err != nil {
		if *verbose {
			log.Printf("Error reading directory: %v\n", err)
		}
		return
	}

	for _, f := range files {
		fp := filepath.Join(directory, f.Name())
		if f.IsDir() {
			waitGroup.Add(1)
			if *verbose {
				log.Printf("Descending into directory: %s\n", fp)
			}
			go scanDirectory(client, fp, scanFileChannel, timeout)
		} else {
			waitGroup.Add(1)
			go func(filePath string) {
				scanFileChannel <- struct{}{}
				if err := scanFile(client, filePath, timeout); err != nil {
					if *verbose {
						log.Printf("Error scanning file: %v\n", err)
					}
				}
				<-scanFileChannel
				waitGroup.Done()
			}(fp)
		}
	}
}

func scanFile(client *amaasclient.AmaasClient, filePath string, timeout time.Duration) error {
	start := time.Now()

	file, err := os.Open(filePath)
	if err != nil {
		logSkippedFile(filePath, err)
		return err
	}
	fileInfo, err := file.Stat()
	file.Close()
	if err != nil {
		logSkippedFile(filePath, err)
		return err
	}

	if fileInfo.Mode().IsDir() || fileInfo.Mode()&os.ModeSymlink != 0 || fileInfo.Mode()&os.ModeNamedPipe != 0 || fileInfo.Mode()&os.ModeSocket != 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	scanErrChan := make(chan error, 1)
	go func() {
		rawResult, err := client.ScanFile(filePath, tags)
		if err == nil {
			var result ScanResult
			err := json.Unmarshal([]byte(rawResult), &result)
			if err == nil {
				if len(result.FoundMalwares) > 0 {
					atomic.AddInt64(&filesWithMalware, 1)
				} else {
					atomic.AddInt64(&filesClean, 1)
				}

				mu.Lock()
				fmt.Fprintf(scanLog, "%s\n", rawResult)
				mu.Unlock()
			}
		}
		scanErrChan <- err
	}()

	select {
	case <-ctx.Done():
		log.Printf("File scan timed out: %s\n", filePath)
		logSkippedFile(filePath, fmt.Errorf("scan timed out"))
		return ctx.Err()
	case scanErr := <-scanErrChan:
		if scanErr != nil {
			logSkippedFile(filePath, scanErr)
			return scanErr
		}
	}

	atomic.AddInt64(&totalScanned, 1)
	mu.Lock()
	fmt.Fprintf(scanLog, "Scanned: %s, Duration: %s\n", filePath, time.Since(start))
	mu.Unlock()
	return nil
}

func logSkippedFile(filePath string, err error) {
	mu.Lock()
	defer mu.Unlock()
	timestamp := time.Now().Format("01-02-2006T15:04")
	skipLogFile := fmt.Sprintf("%s-skipped_files.log", timestamp)
	file, fileErr := os.OpenFile(skipLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if fileErr != nil {
		log.Printf("Error creating skipped files log: %v\n", fileErr)
		return
	}
	defer file.Close()
	logEntry := fmt.Sprintf("Skipped: %s, Error: %v\n", filePath, err)
	file.WriteString(logEntry)
	if *verbose {
		log.Printf("Logged skipped file: %s\n", logEntry)
	}
}
