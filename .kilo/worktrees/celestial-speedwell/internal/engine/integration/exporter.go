package integration

import (
	"encoding/json"
	"fmt"
	"os"
)

// BurpScope represents a Burp Suite project configuration for target scope.
type BurpScope struct {
	Target struct {
		Scope struct {
			AdvancedMode bool `json:"advanced_mode"`
			Include      []struct {
				Enabled  bool   `json:"enabled"`
				Host     string `json:"host"`
				Protocol string `json:"protocol"`
			} `json:"include"`
		} `json:"scope"`
	} `json:"target"`
}

// ExportToBurpConfig generates a Burp Suite project configuration JSON file.
func ExportToBurpConfig(filename string, hosts []string) error {
	var scope BurpScope
	scope.Target.Scope.AdvancedMode = true

	for _, host := range hosts {
		// Add both HTTP and HTTPS
		scope.Target.Scope.Include = append(scope.Target.Scope.Include, struct {
			Enabled  bool   `json:"enabled"`
			Host     string `json:"host"`
			Protocol string `json:"protocol"`
		}{Enabled: true, Host: fmt.Sprintf("^%s$", host), Protocol: "any"})
	}

	data, err := json.MarshalIndent(scope, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// ExportToCaidoTarget generates a simple line-delimited file for Caido import.
func ExportToCaidoTarget(filename string, hosts []string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, host := range hosts {
		if _, err := f.WriteString(host + "\n"); err != nil {
			return err
		}
	}
	return nil
}
