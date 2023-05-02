package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cblakeley/indieauth/client"
)

func main() {
	if len(os.Args) < 5 {
		usage()
		return
	}

	cmd := filepath.Base(os.Args[0])
	hostname := os.Args[1]
	port := os.Args[2]
	certFile := os.Args[3]
	keyFile := os.Args[4]

	client.StartHttpServer(cmd, hostname, port, certFile, keyFile)
}

func usage() {
	fmt.Printf(usageSpecifier, filepath.Base(os.Args[0]))
}

const usageSpecifier = `Usage:
%s <hostname> <port> <pem_certificate_file> <pem_key_file>
`
