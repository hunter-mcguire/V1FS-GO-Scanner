package main

import (
	"flag"          // Package for parsing command-line flags
	"fmt"           // Package for formatted I/O
	"log"           // Package for logging
	"os"            // Package for operating system functionality
	"path/filepath" // Package for file path manipulation
	"strings"       // Package for string manipulation
	"sync"          // Package for concurrency synchronization
	"time"          // Package for time-related functionality

	"github.com/trendmicro/tm-v1-fs-golang-sdk/client" // Importing Trend Micro's Vision One File Scanner SDK
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
	apiKey       = flag.String("apiKey", "", "Vision One API Key")                 // API Key flag
	region       = flag.String("region", "us-east-1", "Vision One Region")         // Region flag
	directory    = flag.String("directory", "", "Path to Directory to scan")       // Directory flag
	verbose      = flag.Bool("verbose", false, "Log all scans to stdout")          // Verbose flag
	maxWorkers   = flag.Int("maxWorkers", 10, "Max number of workers. Minimum: 2") // Max workers flag
	totalScanned = 0                                                               // Counter for total files scanned
	waitGroup    sync.WaitGroup                                                    // WaitGroup for synchronization
	tags         Tags                                                              // Tags for file scanning
)

// Main function
func main() {
	// Parse command-line flags
	flag.Var(&tags, "tags", "Up to 8 strings separated by commas")
	flag.Parse()

	// Check for required arguments
	if *apiKey == "" || *directory == "" || *maxWorkers < 2 {
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

	// Initialize channel for concurrency control
	scanChannel := make(chan struct{}, *maxWorkers)

	// Start scanning the initial directory
	startTime := time.Now()
	scanChannel <- struct{}{} // Add coroutine into channel
	waitGroup.Add(1)
	scanDirectory(scanChannel, client, *directory)

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
		close(scanChannel)
	}()

	// Write scan statistics to log file
	fmt.Fprintf(scanLog, "Total Scan Time: %s\nTotal Files Scanned: %d", timeTaken, totalScanned)
}

// Function to recursively scan a directory
func scanDirectory(channel chan struct{}, client *client.AmaasClient, directory string) error {
	defer func() {
		waitGroup.Done()
		<-channel
	}()

	// Read directory contents
	files, err := os.ReadDir(directory)
	if err != nil {
		if *verbose {
			fmt.Printf("Error reading directory: %v", err)
		}
		log.Printf("Error reading directory: %v", err)
		return err
	}

	// Iterate through directory contents
	for _, f := range files {
		fp := filepath.Join(directory, f.Name())
		if f.IsDir() {
			channel <- struct{}{}
			waitGroup.Add(1)
			go scanDirectory(channel, client, fp) // Recursive call for subdirectories
		} else {
			// Check file size
			fileInfo, err := f.Info()
			if err != nil {
				log.Printf("Error getting file info: %v", err)
				continue
			}
			fileSize := fileInfo.Size()
			if fileSize > oneGB {
				log.Printf("Error: File %s size exceeds 1GB", fp)
				continue
			}
			err = scanFile(client, fp) // Scan individual file
			if err != nil {
				if *verbose {
					fmt.Printf("Error scanning file: %s", f.Name())
				}
				log.Printf("Error scanning file: %s", f.Name())
			}
		}
	}
	return nil
}

// Function to scan an individual file
func scanFile(client *client.AmaasClient, filePath string) error {
	// Remove after testing
	start := time.Now()
	defer func() {
		totalScanned++
		if *verbose {
			fmt.Println(time.Since(start))
		}
	}()

	// Call Vision One SDK to scan the file
	result, err := client.ScanFile(filePath, tags)
	if err != nil {
		return err
	}
	if *verbose {
		fmt.Println(result)
	}
	return nil
}
