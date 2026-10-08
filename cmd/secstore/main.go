package main

import (
	"fmt"
	"os"

	"github.com/Bpoe/secstore/internal/secstore"
)

func main() {
	if err := secstore.Run(os.Args[1:], os.Stdin, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "secstore: error: %v\n", err)
		os.Exit(1)
	}
}
