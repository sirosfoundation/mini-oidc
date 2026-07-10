package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := "9005"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://localhost:%s/health", port) //nolint:gosec // localhost only
	resp, err := client.Get(url)
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
