package main

import (
    "log"
    "os"
    "sync/atomic"
    "time"
    "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

var (
    tags       Tags
    scanLog    *os.File
    totalScanned int64
    filesWithMalware int64
    filesClean int64
)

func initializeClient() {
    var v1ApiKey string
    if k, e := os.LookupEnv("V1_FS_KEY"); e {
        v1ApiKey = k
    } else if *apiKey != "" {
        v1ApiKey = *apiKey
    } else {
        log.Fatal("Use V1_FS_KEY env var or -apiKey parameter")
    }

    if *directory == "" {
        log.Fatal("Missing required argument: -directory")
    }

    var err error
    if *internal_address != "" {
        client, err = amaasclient.NewClientInternal(v1ApiKey, *internal_address, *internal_tls)
    } else {
        client, err = amaasclient.NewClient(v1ApiKey, *region)
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

    authTest := testAuth(client)
    if authTest != nil {
        log.Fatal("Bad Credentials. Check API KEY and role permissions")
    }

    defer client.Destroy()
    setupLogging()
}

func setupLogging() {
    timestamp := time.Now().Format("01-02-2006T15:04")
    logFile, err := os.OpenFile(fmt.Sprintf("%s.error.log", timestamp), os.O_RDWR|os.O_CREATE, 0644)
    if err != nil {
        log.Panic(err)
    }
    log.SetOutput(logFile)
    log.SetFlags(log.Lshortfile | log.LstdFlags)

    scanLog, err = os.OpenFile(fmt.Sprintf("%s-Scan.log", timestamp), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("Error creating scan log file: %v", err)
    }
}
