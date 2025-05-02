package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

// ScanResult represents the scan result structure
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

// Tags type for handling scan tags
type Tags []string

func (t *Tags) String() string {
	return fmt.Sprintf("%v", *t)
}

func (t *Tags) Set(value string) error {
	*t = append(*t, strings.Split(value, ",")...)
	if len(*t) > 8 {
		return fmt.Errorf("maximum 8 tags allowed")
	}
	return nil
}

// Progress tracks scanning progress
type Progress struct {
	currentDir     string
	filesProcessed atomic.Int64
	bytesProcessed atomic.Int64
	startTime      time.Time
	mu            sync.Mutex
}

// ScanWorkerPool manages scan workers
type ScanWorkerPool struct {
	jobs    chan string
	results chan error
	wg      *sync.WaitGroup
}

// IOThrottler controls I/O operations
type IOThrottler struct {
	delay  time.Duration
	tokens chan struct{}
}

// MemoryMonitor tracks memory usage
type MemoryMonitor struct {
	maxMemoryMB int64
	mu          sync.Mutex
	paused      bool
}

// ScanCheckpoint represents a scanning checkpoint
type ScanCheckpoint struct {
	LastScannedPath string    `json:"last_scanned_path"`
	TotalScanned    int64     `json:"total_scanned"`
	Timestamp       time.Time `json:"timestamp"`
}

// Global variables
var (
	// Command line flags
	apiKey           = flag.String("apiKey", "", "Vision One API Key. Can also use V1_FS_KEY env var")
	region           = flag.String("region", "us-east-1", "Vision One Region")
	directory        = flag.String("directory", "", "Path to Directory to scan")
	verbose          = flag.Bool("verbose", false, "Log all scans to stdout")
	pml              = flag.Bool("pml", false, "Enable predictive machine learning detection")
	feedback         = flag.Bool("feedback", false, "Enable SPN feedback")
	maxScanWorkers   = flag.Int("maxWorkers", 100, "Max number concurrent file scans")
	ioThrottle       = flag.Int("iothrottle", 0, "Milliseconds to wait between file operations")
	maxMemoryMB      = flag.Int64("maxMemoryMB", 1024, "Maximum memory usage in MB")
	maxFileSize      = flag.Int64("maxFileSize", 500*1024*1024, "Max file size to scan in bytes")
	minFileSize      = flag.Int64("minFileSize", 1024, "Min file size to scan in bytes")
	skipExtensions   = flag.String("skipExt", ".iso,.vmdk,.vdi,.dll", "Comma-separated list of extensions to skip")
	skipMimeTypes    = flag.String("skipMimeTypes", "application/x-executable,application/x-sharedlib", "Comma-separated list of MIME types to skip")
	excludeDirFile   = flag.String("exclude-dir", "", "Path to file containing directories to exclude")
	internal_address = flag.String("internal_address", "", "Internal Service Gateway Address")
	internal_tls     = flag.Bool("internal_tls", true, "Use TLS for internal Service Gateway")

	// Internal variables
	excludedDirs     map[string]struct{}
	totalScanned     int64
	filesWithMalware int64
	filesClean       int64
	waitGroup        sync.WaitGroup
	tags             Tags
	client           *amaasclient.AmaasClient
	mu              sync.Mutex
	scanLog         *os.File
	errorLog        *log.Logger
	verboseLog      *log.Logger
)

func (p *Progress) PrintStatus() {
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Since(p.startTime)
	bytesPerSec := float64(p.bytesProcessed.Load()) / elapsed.Seconds()

	fmt.Printf("\rProcessed: %d files, %.2f GB, %.2f MB/s, Current: %s",
		p.filesProcessed.Load(),
		float64(p.bytesProcessed.Load())/1e9,
		bytesPerSec/1e6,
		p.currentDir)
}

func NewScanWorkerPool(numWorkers int) *ScanWorkerPool {
	return &ScanWorkerPool{
		jobs:    make(chan string, numWorkers*2),
		results: make(chan error, numWorkers*2),
		wg:      &sync.WaitGroup{},
	}
}

func (p *ScanWorkerPool) Start(client *amaasclient.AmaasClient, throttler *IOThrottler, memMonitor *MemoryMonitor) {
	for i := 0; i < cap(p.jobs); i++ {
		go func() {
			for filePath := range p.jobs {
				err := scanFile(client, filePath, throttler, memMonitor)
				p.results <- err
				p.wg.Done()
			}
		}()
	}
}

func NewIOThrottler(delayMs int) *IOThrottler {
	return &IOThrottler{
		delay:  time.Duration(delayMs) * time.Millisecond,
		tokens: make(chan struct{}, 1),
	}
}

func (t *IOThrottler) Acquire() {
	if t.delay > 0 {
		t.tokens <- struct{}{}
		time.Sleep(t.delay)
		<-t.tokens
	}
}

func NewMemoryMonitor(maxMemoryMB int64) *MemoryMonitor {
	mm := &MemoryMonitor{
		maxMemoryMB: maxMemoryMB,
	}
	go mm.monitor()
	return mm
}

func (m *MemoryMonitor) monitor() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		memoryUsageMB := memStats.Alloc / 1024 / 1024

		m.mu.Lock()
		if memoryUsageMB > uint64(m.maxMemoryMB) && !m.paused {
			m.paused = true
			logError("Memory usage high (%dMB), pausing new scans", memoryUsageMB)
		} else if memoryUsageMB < uint64(m.maxMemoryMB)*80/100 && m.paused {
			m.paused = false
			logVerbose("Memory usage normal (%dMB), resuming scans", memoryUsageMB)
		}
		m.mu.Unlock()
	}
}

func (m *MemoryMonitor) ShouldPause() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.paused
}

func initializeLogging() {
	timestamp := time.Now().Format("01-02-2006T15:04")
	errorLogFile := fmt.Sprintf("%s.error.log", timestamp)
	errorFile, err := os.OpenFile(errorLogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	errorLog = log.New(errorFile, "", log.Lshortfile|log.LstdFlags)

	if *verbose {
		verboseLog = log.New(os.Stdout, "", log.Lshortfile|log.LstdFlags)
	}

	scanLogFile := fmt.Sprintf("%s-Scan.log", timestamp)
	scanLog, err = os.OpenFile(scanLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		errorLog.Fatalf("Error creating scan log file: %v", err)
	}
}

func logError(format string, v ...interface{}) {
	if errorLog != nil {
		errorLog.Printf(format, v...)
	}
}

func logVerbose(format string, v ...interface{}) {
	if *verbose && verboseLog != nil {
		verboseLog.Printf(format, v...)
	}
}

func scanDirectory(client *amaasclient.AmaasClient, directory string, pool *ScanWorkerPool, progress *Progress, throttler *IOThrottler, memMonitor *MemoryMonitor) error {
	checkpoint, _ := loadCheckpoint()
	if checkpoint != nil {
		atomic.StoreInt64(&totalScanned, checkpoint.TotalScanned)
	}

	go periodicCheckpoint(progress)

	logVerbose("Starting scan of directory: %s", directory)

	return filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logError("Error accessing path %s: %v", path, err)
			return nil
		}

		progress.mu.Lock()
		progress.currentDir = filepath.Dir(path)
		progress.mu.Unlock()

		if info.IsDir() {
			logVerbose("Checking directory: %s", path)
			if shouldSkipDirectory(path) {
				logVerbose("Skipping excluded directory: %s", path)
				return filepath.SkipDir
			}
			return nil
		}

		if shouldScanFile(path, info) {
			logVerbose("Queueing file for scan: %s", path)
			pool.wg.Add(1)
			select {
			case pool.jobs <- path:
				atomic.AddInt64(&totalScanned, 1)
				progress.bytesProcessed.Add(info.Size())
				progress.filesProcessed.Add(1)
			default:
				if err := scanFile(client, path, throttler, memMonitor); err != nil {
					logError("Error scanning file %s: %v", path, err)
				}
				pool.wg.Done()
			}
		} else {
			logVerbose("Skipping file due to filters: %s", path)
		}

		return nil
	})
}

func scanFile(client *amaasclient.AmaasClient, filePath string, throttler *IOThrottler, memMonitor *MemoryMonitor) error {
	logVerbose("Starting scan of file: %s", filePath)

	for memMonitor.ShouldPause() {
		logVerbose("Waiting for memory usage to decrease before scanning %s", filePath)
		time.Sleep(time.Second)
	}

	throttler.Acquire()

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		logError("Error accessing file %s: %v", filePath, err)
		return err
	}

	if fileInfo.IsDir() || fileInfo.Mode()&os.ModeSymlink != 0 || fileInfo.Mode()&os.ModeNamedPipe != 0 {
		logVerbose("Skipping non-regular file: %s", filePath)
		return nil
	}

	const maxRetries = 3
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			logVerbose("Retry %d for file: %s", retry, filePath)
			time.Sleep(time.Duration(retry) * time.Second)
		}

		if err := scanFileOnce(client, filePath); err != nil {
			lastErr = err
			logError("Scan attempt %d failed for %s: %v", retry+1, filePath, err)
			if err != context.DeadlineExceeded {
				return err
			}
			continue
		}
		
		logVerbose("Successfully scanned file: %s", filePath)
		atomic.AddInt64(&totalScanned, 1)
		return nil
	}

	return fmt.Errorf("max retries exceeded for %s: %v", filePath, lastErr)
}

func scanFileOnce(client *amaasclient.AmaasClient, filePath string) error {
	rawResult, err := client.ScanFile(filePath, tags)
	if err != nil {
		return err
	}

	var result ScanResult
	if err := json.Unmarshal([]byte(rawResult), &result); err != nil {
		return err
	}

	if len(result.FoundMalwares) > 0 {
		atomic.AddInt64(&filesWithMalware, 1)
	} else {
		atomic.AddInt64(&filesClean, 1)
	}

	mu.Lock()
	fmt.Fprintf(scanLog, "%s\n", rawResult)
	mu.Unlock()

	return nil
}

func shouldSkipDirectory(path string) bool {
	normalizedPath := filepath.Clean(path)
	for excludedDir := range excludedDirs {
		if strings.HasPrefix(normalizedPath, filepath.Clean(excludedDir)) {
			return true
		}
	}
	return false
}

func shouldScanFile(path string, info os.FileInfo) bool {
	if info.Size() > *maxFileSize || info.Size() < *minFileSize {
		return false
	}

	ext := strings.ToLower(filepath.Ext(path))
	for _, skipExt := range strings.Split(*skipExtensions, ",") {
		if ext == strings.TrimSpace(skipExt) {
			return false
		}
	}

	return true
}

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

	return scanner.Err()
}

func loadCheckpoint() (*ScanCheckpoint, error) {
    data, err := os.ReadFile("scan_checkpoint.json")
    if err != nil {
        if os.IsNotExist(err) {
            return nil, nil
        }
        return nil, err
    }

    var checkpoint ScanCheckpoint
    err = json.Unmarshal(data, &checkpoint)
    return &checkpoint, err
}

func saveCheckpoint(checkpoint ScanCheckpoint) error {
    data, err := json.Marshal(checkpoint)
    if err != nil {
        return err
    }
    return os.WriteFile("scan_checkpoint.json", data, 0644)
}

func periodicCheckpoint(progress *Progress) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        checkpoint := ScanCheckpoint{
            LastScannedPath: progress.currentDir,
            TotalScanned:    atomic.LoadInt64(&totalScanned),
            Timestamp:       time.Now(),
        }
        if err := saveCheckpoint(checkpoint); err != nil {
            logError("Error saving checkpoint: %v", err)
        }
    }
}

func validateAndGetApiKey() string {
    if k, exists := os.LookupEnv("V1_FS_KEY"); exists {
        return k
    }
    if *apiKey == "" {
        flag.PrintDefaults()
        log.Fatal("Use V1_FS_KEY env var or -apiKey parameter")
    }
    return *apiKey
}

func validateDirectory() {
    if *directory == "" {
        flag.PrintDefaults()
        log.Fatal("Missing required argument: -directory")
    }
}

func initializeClient(apiKey string) {
    var err error
    if *internal_address != "" {
        client, err = amaasclient.NewClientInternal(apiKey, *internal_address, *internal_tls)
    } else {
        client, err = amaasclient.NewClient(apiKey, *region)
    }
    if err != nil {
        log.Fatalf("Error creating client: %v", err)
    }

    if *pml {
        client.SetPMLEnable()
        logVerbose("PML scanning enabled")
    }
    if *feedback {
        client.SetFeedbackEnable()
        logVerbose("Feedback enabled")
    }

    if err := testAuth(client); err != nil {
        log.Fatal("Bad Credentials. Check API KEY and role permissions")
    }
}

func reportProgress(progress *Progress) {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    for range ticker.C {
        progress.PrintStatus()
    }
}

func printSummary(startTime time.Time) {
    timeTaken := time.Since(startTime)
    
    mu.Lock()
    fmt.Fprintf(scanLog, "\n--- Final Scan Summary ---\n")
    fmt.Fprintf(scanLog, "Total Files Scanned: %d\n", atomic.LoadInt64(&totalScanned))
    fmt.Fprintf(scanLog, "Files with Malware: %d\n", atomic.LoadInt64(&filesWithMalware))
    fmt.Fprintf(scanLog, "Files Clean: %d\n", atomic.LoadInt64(&filesClean))
    fmt.Fprintf(scanLog, "Total Scan Time: %s\n", timeTaken)
    mu.Unlock()

    fmt.Println("\n--- Final Scan Summary ---")
    fmt.Printf("Total Files Scanned: %d\n", atomic.LoadInt64(&totalScanned))
    fmt.Printf("Files with Malware: %d\n", atomic.LoadInt64(&filesWithMalware))
    fmt.Printf("Files Clean: %d\n", atomic.LoadInt64(&filesClean))
    fmt.Printf("Total Scan Time: %s\n", timeTaken)
}

func main() {
    // Parse command-line flags
    flag.Var(&tags, "tags", "Up to 8 strings separated by commas")
    flag.Parse()

    // Validate required arguments
    v1ApiKey := validateAndGetApiKey()
    validateDirectory()

    // Initialize components
    initializeLogging()
    defer scanLog.Close()

    // Load exclusion directories
    if err := loadExcludedDirs(); err != nil {
        logError("Error loading exclusion directories: %v", err)
        os.Exit(1)
    }

    // Initialize client
    initializeClient(v1ApiKey)
    defer client.Destroy()

    // Initialize scanning components
    progress := &Progress{startTime: time.Now()}
    memMonitor := NewMemoryMonitor(*maxMemoryMB)
    ioThrottler := NewIOThrottler(*ioThrottle)
    pool := NewScanWorkerPool(*maxScanWorkers)

    // Start progress reporting
    go reportProgress(progress)

    // Start scanning
    startTime := time.Now()
    pool.Start(client, ioThrottler, memMonitor)

    // Start directory scanning
    waitGroup.Add(1)
    err := scanDirectory(client, *directory, pool, progress, ioThrottler, memMonitor)
    if err != nil {
        logError("Error scanning directory: %v", err)
        os.Exit(1)
    }

    // Wait for completion
    close(pool.jobs)
    pool.wg.Wait()

    // Print final summary
    printSummary(startTime)
}
