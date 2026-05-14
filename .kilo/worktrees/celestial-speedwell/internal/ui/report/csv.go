package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

func WriteCSV(w io.Writer, model *DataModel) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{"host", "priority", "score", "tags", "reasons", "suggested_tests", "evidence_count"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, insight := range model.Insights {
		if err := writer.Write([]string{
			insight.Host,
			insight.Priority,
			fmt.Sprintf("%d", insight.Score),
			strings.Join(insight.Tags, ", "),
			strings.Join(insight.Reasons, "; "),
			strings.Join(insight.SuggestedTests, "; "),
			fmt.Sprintf("%d", insight.EvidenceCount),
		}); err != nil {
			return err
		}
	}
	return nil
}
