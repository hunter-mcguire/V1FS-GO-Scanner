package main

import (
    "fmt"
    "log"
    "strings"
    "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

type Tags []string

func (tags *Tags) String() string {
    return fmt.Sprintf("%v", *tags)
}

func (tags *Tags) Set(value string) error {
    *tags = append(*tags, strings.Split(value, ",")...)
    if len(*tags) > 8 {
        log.Fatalf("tags accepts up to 8 strings")
    }
    return nil
}

func testAuth(client *amaasclient.AmaasClient) error {
    _, err := client.ScanBuffer([]byte(""), "testAuth", nil)
    return err
}
