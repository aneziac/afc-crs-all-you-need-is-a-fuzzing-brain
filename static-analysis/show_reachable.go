package main

import (
	"encoding/json"
	"fmt"
	"static-analysis/internal/engine"
)

func main() {
	functions, err := engine.ProcessCFileDebug("/home/nate/code/minimal/local-test-sqlite3-full-01/afc-sqlite3/test/ossfuzz.c")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Find the LLVMFuzzerTestOneInput function and show reachable functions in JSON format
	var reachableFunctions []map[string]interface{}

	for _, fn := range functions {
		if fn.Name != "" && fn.FilePath != "" && fn.SourceCode != "" {
			reachableFunctions = append(reachableFunctions, map[string]interface{}{
				"Name":       fn.Name,
				"FilePath":   fn.FilePath,
				"StartLine":  fn.StartLine,
				"EndLine":    fn.EndLine,
				"SourceCode": fn.SourceCode,
			})
		}
	}

	fmt.Printf("Received %d reachable_functions: ", len(reachableFunctions))
	jsonData, _ := json.MarshalIndent(reachableFunctions[:20], "", "  ") // Show first 20
	fmt.Println(string(jsonData))
}
