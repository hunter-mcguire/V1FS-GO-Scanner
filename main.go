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

	"github.com/trendmicro/tm-v1-fs-golang-sdk/client"
)

// Constants and Types
const oneGB = 1 << 30 // Constant representing 1GB in bytes

// Tags represents a slice of strings used for tagging files during scanning
type Tags []string

// String returns the string representation of Tags
func (tags *Tags) String() string {
	return fmt.Sprintf("%v", *tags)
}

// Set sets the value of Tags
func (tags *Tags) Set(value string) error {
	*tags = append(*tags, strings.Split(value, ",")...)
	if len(*tags) > 8 {
		log.Fatalf("tags accepts up to 8 strings")
	}
	return nil
}

// Variables
var (
	apiKey         = flag.String("apiKey", "", "Vision One API Key")
	region         = flag.String("region", "us-east-1", "Vision One Region")
	directory      = flag.String("directory", "", "Path to Directory to scan")
	verbose        = flag.Bool("verbose", false, "Log all scans to stdout")
	maxScanWorkers = flag.Int("maxWorkers", -1, "Max number concurrent file scans. Default: Unlimited")

	totalScanned int64          // Counter for total files scanned, ensure thread-safe operations
	waitGroup    sync.WaitGroup // WaitGroup for synchronization
	tags         Tags           // Tags for file scanning
)

func main() {
	// Parse command-line flags
	flag.Var(&tags, "tags", "Up to 8 strings separated by commas")
	flag.Parse()

	// Check for required arguments
	if *apiKey == "" || *directory == "" {
		flag.PrintDefaults()
		log.Fatal("Missing required arguments")
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

	// Create Vision One client
	client, err := client.NewClient(*apiKey, *region)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}
	defer client.Destroy()

	// Initialize channel for file scan concurrency control with an appropriate limit
	scanFileChannel := make(chan struct{}, func() int {
		if *maxScanWorkers == -1 {
			return 1000 // practically "unlimited" value
		}
		return *maxScanWorkers
	}())

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
}

// Function to recursively scan a directory
func scanDirectory(client *client.AmaasClient, directory string, scanFileChannel chan struct{}) {
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
			fileInfo, err := f.Info()
			if err != nil || fileInfo.Size() > oneGB {
				continue // Skip if error or file size exceeds 1GB
			}
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
func scanFile(client *client.AmaasClient, filePath string) error {
	start := time.Now()
	defer func() {
		atomic.AddInt64(&totalScanned, 1) // Thread-safe increment
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
