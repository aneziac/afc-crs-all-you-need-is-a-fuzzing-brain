package main

import (
	"fmt"
	"static-analysis/internal/engine"
)

func main() {
	functions, err := engine.ProcessCFileDebug("/home/nate/code/minimal/local-test-sqlite3-full-01/afc-sqlite3/test/ossfuzz.c")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Found %d functions\n", len(functions))
	for key, fn := range functions {
		fmt.Printf("Function: %s -> %s\n", key, fn.Name)
	}
}
