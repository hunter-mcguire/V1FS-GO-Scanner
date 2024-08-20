package main

import (
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

	totalScanned int64                    // Counter for total files scanned, ensure thread-safe operations
	waitGroup    sync.WaitGroup           // WaitGroup for synchronization
	tags         Tags                     // Tags for file scanning
	client       *amaasclient.AmaasClient // FS Client
	scannedFiles []string                 // Slice to store scanned file paths
	mu           sync.Mutex               // Mutex for thread-safe access to scannedFiles
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

	// Open scan log file
	scanLog, err := os.OpenFile(timestamp+"-Scan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Error:", err)
	}
	defer func() {
		scanLog.Close()
		close(scanFileChannel) // Close the channel
	}()

	// Write scan statistics to log file
	fmt.Fprintf(scanLog, "Total Scan Time: %s\nTotal Files Scanned: %d\n", timeTaken, atomic.LoadInt64(&totalScanned))

	// Output the list of scanned files
	fmt.Println("Files Scanned:")
	for _, file := range scannedFiles {
		fmt.Println(file)
	}
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
		scannedFiles = append(scannedFiles, filePath) // Add scanned file path to the list
		mu.Unlock()
		if *verbose {
			fmt.Printf("Scanned: %s, Duration: %s\n", filePath, time.Since(start))
		}
	}()

	// Call Vision One SDK to scan the file
	result, err := client.ScanFile(filePath, tags)
	if *verbose && err == nil {
		fmt.Println(result)
	}
	return err
}
