package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
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

// ScanWorkerPool manages scan workers
type ScanWorkerPool struct {
	jobs    chan string
	results chan error
	wg      *sync.WaitGroup
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

// IOThrottler controls I/O operations
type IOThrottler struct {
	delay  time.Duration
	tokens chan struct{}
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

// MemoryMonitor tracks memory usage
type MemoryMonitor struct {
	maxMemoryMB int64
	mu          sync.Mutex
	paused      bool
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
			log.Printf("Memory usage high (%dMB), pausing new scans", memoryUsageMB)
		} else if memoryUsageMB < uint64(m.maxMemoryMB)*80/100 && m.paused {
			m.paused = false
			log.Printf("Memory usage normal (%dMB), resuming scans", memoryUsageMB)
		}
		m.mu.Unlock()
	}
}

func (m *MemoryMonitor) ShouldPause() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.paused
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
)

func main() {
	// Parse command-line flags
	flag.Var(&tags, "tags", "Up to 8 strings separated by commas")
	flag.Parse()

	// Validate required arguments
	v1ApiKey := validateAndGetApiKey()
	validateDirectory()

	// Load exclusion directories
	if err := loadExcludedDirs(); err != nil {
		log.Fatalf("Error loading exclusion directories: %v", err)
	}

	// Initialize client
	initializeClient(v1ApiKey)
	defer client.Destroy()

	// Initialize components
	progress := &Progress{startTime: time.Now()}
	memMonitor := NewMemoryMonitor(*maxMemoryMB)
	ioThrottler := NewIOThrottler(*ioThrottle)
	pool := NewScanWorkerPool(*maxScanWorkers)

	// Initialize logging
	initializeLogging()
	defer scanLog.Close()

	// Start progress reporting
	go reportProgress(progress)

	// Start scanning
	startTime := time.Now()
	pool.Start(client, ioThrottler, memMonitor)

	// Start directory scanning
	waitGroup.Add(1)
	err := scanDirectory(client, *directory, pool, progress, ioThrottler, memMonitor)
	if err != nil {
		log.Printf("Error scanning directory: %v", err)
	}

	// Wait for completion
	close(pool.jobs)
	pool.wg.Wait()

	// Print final summary
	printSummary(startTime)
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
	}
	if *feedback {
		client.SetFeedbackEnable()
	}

	if err := testAuth(client); err != nil {
		log.Fatal("Bad Credentials. Check API KEY and role permissions")
	}
}

func initializeLogging() {
	timestamp := time.Now().Format("01-02-2006T15:04")
	logFile := fmt.Sprintf("%s.error.log", timestamp)
	errorLog, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(errorLog)
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	scanLogFile := fmt.Sprintf("%s-Scan.log", timestamp)
	scanLog, err = os.OpenFile(scanLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error creating scan log file: %v", err)
	}
}

func reportProgress(progress *Progress) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		progress.PrintStatus()
	}
}

func scanDirectory(client *amaasclient.AmaasClient, directory string, pool *ScanWorkerPool, progress *Progress, throttler *IOThrottler, memMonitor *MemoryMonitor) error {
	// Load checkpoint if exists
	checkpoint, _ := loadCheckpoint()
	if checkpoint != nil {
		atomic.StoreInt64(&totalScanned, checkpoint.TotalScanned)
	}

	// Start periodic checkpoint saving
	go periodicCheckpoint(progress)

	// Walk directory
	return filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Update progress
		progress.mu.Lock()
		progress.currentDir = filepath.Dir(path)
		progress.mu.Unlock()

		// Check if directory should be skipped
		if info.IsDir() {
			if shouldSkipDirectory(path) {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if file should be scanned
		if shouldScanFile(path, info) {
			pool.wg.Add(1)
			pool.jobs <- path
		}

		return nil
	})
}

func shouldSkipDirectory(path string) bool {
	normalizedPath := filepath.Clean(path)
	for excludedDir := range excludedDirs {
		if strings.HasPrefix(normalizedPath, filepath.Clean(excludedDir)) {
			if *verbose {
				log.Printf("Skipping excluded directory: %s\n", path)
			}
			return true
		}
	}
	return false
}

func shouldScanFile(path string, info os.FileInfo) bool {
	// Check file size
	if info.Size() > *maxFileSize || info.Size() < *minFileSize {
		return false
	}

	// Check extension
	ext := strings.ToLower(filepath.Ext(path))
	for _, skipExt := range strings.Split(*skipExtensions, ",") {
		if ext == strings.TrimSpace(skipExt) {
			return false
		}
	}

	return true
}

func scanFile(client *amaasclient.AmaasClient, filePath string, throttler *IOThrottler, memMonitor *MemoryMonitor) error {
	start := time.Now()

	// Wait if memory usage is too high
	for memMonitor.ShouldPause() {
		time.Sleep(time.Second)
	}

	// Apply I/O throttling
	throttler.Acquire()

	// Scan with retry
	const maxRetries = 3
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			time.Sleep(time.Duration(retry) * time.Second)
		}

		err := scanFileOnce(client, filePath)
		if err == nil {
			return nil
		}

		if err == context.DeadlineExceeded {
			lastErr = err
			continue
		}

		return err
	}

	return fmt.Errorf("max retries exceeded: %v", lastErr)
}

func scanFileOnce(client *amaasclient.AmaasClient, filePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rawResult, err := client.ScanFile(filePath, tags)
	if err != nil {
		return err
	}

	var result ScanResult
	if err := json.Unm
