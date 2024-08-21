package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "time"
)

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

    client *amaasclient.AmaasClient
)

func main() {
    // Command-line flags parsing and validation
    flag.Var(&tags, "tags", "Up to 8 strings separated by commas")
    flag.Parse()

    // Initialize the client and start scanning
    initializeClient()
    startScanning()
}
