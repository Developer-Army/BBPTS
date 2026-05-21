package analyze

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteEvidenceBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	insights := []Insight{
		{Host: "a.example.com", Score: 50, Confidence: 80, Priority: "high"},
		{Host: "b.example.com", Score: 40, Confidence: 70, Priority: "medium"},
	}
	if err := WriteEvidenceBundle(path, insights, 10); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bundle EvidenceBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Count != 2 || len(bundle.Items) != 2 {
		t.Fatalf("bundle: %+v", bundle)
	}
}
