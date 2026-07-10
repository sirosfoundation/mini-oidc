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
	resp, err := client.Get(fmt.Sprintf("http://localhost:%s/health", port))
	if err != nil {
		os.Exit(1)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
