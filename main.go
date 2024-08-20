package main

import (
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
	pml              = flag.Bool("pml", false, "enable predictive machine learning detection")
	feedback         = flag.Bool("feedback", false, "enable SPN feedback")
	maxScanWorkers   = flag.Int("maxWorkers", 100, "Max number concurrent file scans Unlimited: -1")
	internal_address = flag.String("internal_address", "", "Internal Service Gateway Address")
	internal_tls     = flag.Bool("internal_tls", true, "Use TLS for internal Service Gateway")

	totalScanned    int64                    // Counter for total files scanned, ensure thread-safe operations
	filesWithMalware int64                   // Counter for files with malware found
	filesClean      int64                    // Counter for files with no issues
	waitGroup       sync.WaitGroup           // WaitGroup for synchronization
	tags            Tags                     // Tags for file scanning
	client          *amaasclient.AmaasClient // FS Client
	mu              sync.Mutex               // Mutex for thread-safe access to log file
	scanLog         *os.File                 // File to log scanned files and results
)

func testAuth(client *amaasclient.AmaasClient) error {
	_, err := client.ScanBuffer([]byte(""), "testAuth", nil)
	if err != nil {
		return err
	} else {
		return nil
	}
}

func main() {
	// Parse command-line flags
	flag.Var(&tags, "tags", "Up to 8 strings separated by commas")
	flag.Parse()

	var v1ApiKey string
	var err error

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

	// Create Vision One client
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

	if *pml {
		client.SetPMLEnable()
	}

	if *feedback {
		client.SetFeedbackEnable()
	}

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

	// Initialize channel for file scan concurrency control with an appropriate limit
	var scanFileChannel chan struct{}

	func() {
		if *maxScanWorkers == -1 {
			scanFileChannel = make(chan struct{})
		} else {
			scanFileChannel = make(chan struct{}, *maxScanWorkers)
		}
	}()

	// Start scanning the initial directory
	startTime := time.Now()
	waitGroup.Add(1)
	go scanDirectory(client, *directory, scanFileChannel)

	// Wait for all goroutines to finish before exiting
	waitGroup.Wait()

	// Calculate total scan time
	timeTaken := time.Since(startTime)

	// Write scan statistics and GRC summary to log file
	mu.Lock()
	fmt.Fprintf(scanLog, "Total Scan Time: %s\nTotal Files Scanned: %d\nFiles with Malware: %d\nFiles Clean: %d\n", timeTaken, atomic.LoadInt64(&totalScanned), atomic.LoadInt64(&filesWithMalware), atomic.LoadInt64(&filesClean))
	mu.Unlock()

	// Output the summary to the terminal
	fmt.Println("\n--- Scan Summary ---")
	fmt.Printf("Total Files Scanned: %d\n", atomic.LoadInt64(&totalScanned))
	fmt.Printf("Files with Malware: %d\n", atomic.LoadInt64(&filesWithMalware))
	fmt.Printf("Files Clean: %d\n", atomic.LoadInt64(&filesClean))
	fmt.Printf("Total Scan Time: %s\n", timeTaken)
}

// Function to recursively scan a directory
func scanDirectory(client *amaasclient.AmaasClient, directory string, scanFileChannel chan struct{}) {
	defer waitGroup.Done()

	// Read directory contents
	files, err := os.ReadDir(directory)
	if err != nil {
		log.Printf("Error reading directory: %v\n", err)
		return
	}

	for _, f := range files {
		fp := filepath.Join(directory, f.Name())
		if f.IsDir() {
			waitGroup.Add(1)
			go scanDirectory(client, fp, scanFileChannel) // Recursive call for subdirectories
		} else {
			waitGroup.Add(1)
			go func(filePath string) {
				scanFileChannel <- struct{}{} // Control concurrency
				if err := scanFile(client, filePath); err != nil {
					log.Printf("Error scanning file: %v\n", err)
				}
				<-scanFileChannel
				waitGroup.Done()
			}(fp)
		}
	}
}

// Function to scan an individual file
func scanFile(client *amaasclient.AmaasClient, filePath string) error {
	start := time.Now()
	defer func() {
		atomic.AddInt64(&totalScanned, 1) // Thread-safe increment
		mu.Lock()
		// Log the scanned file path and scan result to the scan log
		fmt.Fprintf(scanLog, "Scanned: %s, Duration: %s\n", filePath, time.Since(start))
		mu.Unlock()
	}()

	// Output the file being scanned
	fmt.Printf("Scanning: %s\n", filePath)

	// Call Vision One SDK to scan the file
	rawResult, err := client.ScanFile(filePath, tags)
	if err == nil {
		var result ScanResult
		err := json.Unmarshal([]byte(rawResult), &result)
		if err != nil {
			log.Printf("Error parsing scan result for file %s: %v\n", filePath, err)
			return err
		}

		// Analyze the scan result
		if len(result.FoundMalwares) > 0 {
			atomic.AddInt64(&filesWithMalware, 1)
		} else {
			atomic.AddInt64(&filesClean, 1)
		}

		// Log the result of the scan in JSON format (for detailed review)
		mu.Lock()
		fmt.Fprintf(scanLog, "%s\n", rawResult)
		mu.Unlock()
	}

	// Print concise output to the terminal
	if err == nil {
		fmt.Printf("Scanned: %s [scanned in %s]\n", filePath, time.Since(start))
	}
	return err // Return any error encountered during the scan
}
