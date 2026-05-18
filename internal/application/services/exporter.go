package services

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ExportToBurpXML generates a Burp Suite XML findings file for import into
// Burp Scanner. Each host is exported as a Burp item with full scope coverage.
func ExportToBurpXML(filename string, hosts []string) error {
    f, err := os.Create(filename)
    if err != nil {
        return fmt.Errorf("creating burp xml file: %w", err)
    }
    defer f.Close()

    if _, err := f.WriteString(`<?xml version="1.0"?>` + "\n<items burpVersion=\"2023.1\" exportTime=\"" + time.Now().UTC().Format(time.RFC3339) + "\">\n"); err != nil {
        return err
    }
    for _, host := range hosts {
        host = strings.TrimSpace(host)
        if host == "" {
            continue
        }
        protocol := "https"
        if strings.HasPrefix(host, "http://") {
            protocol = "http"
            host = strings.TrimPrefix(host, "http://")
        } else {
            host = strings.TrimPrefix(host, "https://")
        }
        item := fmt.Sprintf("  <item>\n    <url>%s://%s/</url>\n    <host>%s</host>\n    <port>%s</port>\n    <protocol>%s</protocol>\n    <method>GET</method>\n    <path>/</path>\n    <extension/>\n    <request/>\n    <status/>\n    <responselength/>\n    <mimetype/>\n    <response/>\n    <comment>BBPTS recon target</comment>\n  </item>\n",
            protocol, host, host, map[string]string{"https": "443", "http": "80"}[protocol], protocol)
        if _, err := f.WriteString(item); err != nil {
            return err
        }
    }
    _, err = f.WriteString("</items>\n")
    return err
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
