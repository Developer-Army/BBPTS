package report

import (
	"github.com/Developer-Army/BBPTS/internal/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/engine/recon"
)

type DataModel struct {
	Targets  []string          `json:"targets"`
	Events   []recon.Event     `json:"events"`
	Insights []analyze.Insight `json:"insights"`
}

func NewReportModel(targets []string, events []recon.Event, insights []analyze.Insight) *DataModel {
	return &DataModel{Targets: targets, Events: events, Insights: insights}
}
