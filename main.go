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
	pml              = flag.Bool("pml", false, "enable predictive machine learning detection")
	feedback         = flag.Bool("feedback", false, "enable SPN feedback")
	maxScanWorkers   = flag.Int("maxWorkers", 100, "Max number concurrent file scans Unlimited: -1")
	internal_address = flag.String("internal_address", "", "Internal Service Gateway Address")
	internal_tls     = flag.Bool("internal_tls", true, "Use TLS for internal Service Gateway")
	excludeDirFile = flag.String("exclude-dir", "", "Path to file containing directories to exclude from the scan")
    
	excludedDirs   map[string]struct{} // Set to store directories to exclude from the scan
	totalScanned    int64                    // Counter for total files scanned, ensure thread-safe operations
	filesWithMalware int64                   // Counter for files with malware found
	filesClean      int64                    // Counter for files with no issues
	waitGroup       sync.WaitGroup           // WaitGroup for synchronization
	tags            Tags                     // Tags for file scanning
	client          *amaasclient.AmaasClient // FS Client
	mu              sync.Mutex               // Mutex for thread-safe access to log file
	scanLog         *os.File                 // File to log scanned files and results
	timeoutLimit = flag.Int("timeoutlimit", 10, "Timeout limit in seconds for scanning a file")
)

func testAuth(client *amaasclient.AmaasClient) error {
	_, err := client.ScanBuffer([]byte(""), "testAuth", nil)
	if err != nil {
		return err
	} else {
		return nil
	}
}

func loadExcludedDirs() error {
    if *excludeDirFile == "" {
        return nil // No exclusion file provided
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
	var err error

	// Get timeout limit from the flag
	timeout := time.Duration(*timeoutLimit) * time.Second


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
	go scanDirectory(client, *directory, scanFileChannel, timeout)

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
	fmt.Printf("Total Scan Time: %s\n", time.Since(startTime))
}

// Function to recursively scan a directory
func scanDirectory(client *amaasclient.AmaasClient, directory string, scanFileChannel chan struct{}, timeout time.Duration) {
    defer waitGroup.Done() // Ensure WaitGroup counter decrements when the function exits

    // Normalize the directory path
    normalizedDir := filepath.Clean(directory)

    // Check if the directory or any parent directory is in the exclusion list
    for excludedDir := range excludedDirs {
        normalizedExcludedDir := filepath.Clean(excludedDir)
        if strings.HasPrefix(normalizedDir, normalizedExcludedDir) {
            if *verbose {
                log.Printf("Skipping excluded directory or subdirectory: %s\n", directory)
            }
            return // Skip this directory entirely
        }
    }

    // Read directory contents
    files, err := os.ReadDir(directory)
    if err != nil {
        if *verbose {
            log.Printf("Error reading directory: %v\n", err)
        }
        return // Exit if the directory cannot be read
    }

    for _, f := range files { // Iterate over directory contents
        fp := filepath.Join(directory, f.Name())
        if f.IsDir() { // Process subdirectories recursively
            waitGroup.Add(1)
            if *verbose {
                log.Printf("Descending into directory: %s\n", fp)
            }
            go scanDirectory(client, fp, scanFileChannel, timeout)
        } else { // Process individual files
            waitGroup.Add(1)
            go func(filePath string) {
                scanFileChannel <- struct{}{} // Concurrency control
                if *verbose {
                    log.Printf("Considering file: %s\n", filePath)
                }
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

    // Log the file being considered if verbose mode is on
    if *verbose {
        log.Printf("Considering file: %s\n", filePath)
    }

    // Try to open the file to check if it can be accessed
    file, err := os.Open(filePath)
    if err != nil {
        if *verbose {
            log.Printf("Error opening file %s: %v\n", filePath, err)
        }
        logSkippedFile(filePath, err)
        return err
    }

    // Get file information to check its type
    fileInfo, err := file.Stat()
    file.Close() // Close the file as soon as we're done with it

    if err != nil {
        if *verbose {
            log.Printf("Error getting file info for %s: %v\n", filePath, err)
        }
        logSkippedFile(filePath, err)
        return err
    }

    // Skip special files
    if fileInfo.Mode().IsDir() || fileInfo.Mode()&os.ModeSymlink != 0 || fileInfo.Mode()&os.ModeNamedPipe != 0 || fileInfo.Mode()&os.ModeSocket != 0 {
        if *verbose {
            log.Printf("Skipping special file %s\n", filePath)
        }
        return nil
    }

    // Use a context with a timeout for scanning
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    scanErrChan := make(chan error, 1)

    // Start scanning in a separate goroutine
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
            log.Printf("Error scanning file %s: %v\n", filePath, scanErr)
            logSkippedFile(filePath, scanErr)
            return scanErr
        }
    }

    atomic.AddInt64(&totalScanned, 1) // Thread-safe increment
    mu.Lock()
    // Log the scanned file path and scan duration
    fmt.Fprintf(scanLog, "Scanned: %s, Duration: %s\n", filePath, time.Since(start))
    mu.Unlock()

    if *verbose {
        fmt.Printf("Scanned: %s [scanned in %s]\n", filePath, time.Since(start))
    }

    return nil
}

// Function to log skipped files due to errors
func logSkippedFile(filePath string, err error) {
    mu.Lock()
    defer mu.Unlock()

    // Write the skipped file details to the pre-initialized log file
    logEntry := fmt.Sprintf("Skipped: %s, Error: %v\n", filePath, err)
    _, fileErr := skippedFilesLog.WriteString(logEntry)
    if fileErr != nil {
        log.Printf("Error writing to skipped files log: %v\n", fileErr)
        return
    }

    if *verbose {
        log.Printf("Logged skipped file: %s\n", logEntry)
    }
}
