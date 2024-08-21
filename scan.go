package main

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "sync"
    "sync/atomic"
    "time"
    "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

var waitGroup sync.WaitGroup

func startScanning() {
    var scanFileChannel chan struct{}
    if *maxScanWorkers == -1 {
        scanFileChannel = make(chan struct{})
    } else {
        scanFileChannel = make(chan struct{}, *maxScanWorkers)
    }

    startTime := time.Now()
    waitGroup.Add(1)
    go scanDirectory(client, *directory, scanFileChannel)

    waitGroup.Wait()

    timeTaken := time.Since(startTime)
    logScanSummary(timeTaken)
}

func scanDirectory(client *amaasclient.AmaasClient, directory string, scanFileChannel chan struct{}) {
    defer waitGroup.Done()

    files, err := os.ReadDir(directory)
    if err != nil {
        log.Printf("Error reading directory: %v\n", err)
        return
    }

    for _, f := range files {
        fp := filepath.Join(directory, f.Name())
        if f.IsDir() {
            waitGroup.Add(1)
            go scanDirectory(client, fp, scanFileChannel)
        } else {
            waitGroup.Add(1)
            go func(filePath string) {
                scanFileChannel <- struct{}{}
                if err := scanFile(client, filePath); err != nil {
                    log.Printf("Error scanning file: %v\n", err)
                }
                <-scanFileChannel
                waitGroup.Done()
            }(fp)
        }
    }
}

func scanFile(client *amaasclient.AmaasClient, filePath string) error {
    start := time.Now()
    defer func() {
        atomic.AddInt64(&totalScanned, 1)
        fmt.Fprintf(scanLog, "Scanned: %s, Duration: %s\n", filePath, time.Since(start))
    }()

    rawResult, err := client.ScanFile(filePath, tags)
    if err == nil {
        var result ScanResult
        err := json.Unmarshal([]byte(rawResult), &result)
        if err != nil {
            log.Printf("Error parsing scan result for file %s: %v\n", filePath, err)
            return err
        }

        if len(result.FoundMalwares) > 0 {
            atomic.AddInt64(&filesWithMalware, 1)
        } else {
            atomic.AddInt64(&filesClean, 1)
        }

        fmt.Fprintf(scanLog, "%s\n", rawResult)
    }

    fmt.Printf("Scanned: %s [scanned in %s]\n", filePath, time.Since(start))
    return err
}

func logScanSummary(timeTaken time.Duration) {
    fmt.Fprintf(scanLog, "Total Scan Time: %s\nTotal Files Scanned: %d\nFiles with Malware: %d\nFiles Clean: %d\n",
        timeTaken, atomic.LoadInt64(&totalScanned), atomic.LoadInt64(&filesWithMalware), atomic.LoadInt64(&filesClean))

    fmt.Println("\n--- Scan Summary ---")
    fmt.Printf("Total Files Scanned: %d\n", atomic.LoadInt64(&totalScanned))
    fmt.Printf("Files with Malware: %d\n", atomic.LoadInt64(&filesWithMalware))
    fmt.Printf("Files Clean: %d\n", atomic.LoadInt64(&filesClean))
    fmt.Printf("Total Scan Time: %s\n", timeTaken)
}
