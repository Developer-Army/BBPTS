package services

import (
	"context"
	"log/slog"
	"sort"
	"sync"

	"github.com/Developer-Army/BBPTS/internal/domain/assets"
	"github.com/Developer-Army/BBPTS/internal/domain/ownership"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

type WorkerPool struct {
	workers int
	limiter *rate.Limiter
}

func NewWorkerPool(workers int, r rate.Limit) *WorkerPool {
	var lim *rate.Limiter
	if r > 0 {
		lim = rate.NewLimiter(r, int(r)*2)
	}
	return &WorkerPool{
		workers: workers,
		limiter: lim,
	}
}

func (p *WorkerPool) Process(ctx context.Context, targets []string, fn func(ctx context.Context, target string) ([]Event, error)) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	g, ctx := errgroup.WithContext(ctx)

	scorer := recon.NewScorer()
	type scoredTarget struct {
		target string
		score  int
	}
	store := storage.FromContext(ctx)

	var assetsMap map[string]*assets.Asset
	var evidenceCounts map[string]int
	var attackPaths map[string]bool

	if store != nil {
		var err error
		assetsMap, err = store.GetAssetsByIDs(ctx, targets)
		if err != nil {
			slog.Warn("Failed to batch get assets", "error", err)
		}
		evidenceCounts, err = store.GetEvidenceCounts(ctx, targets)
		if err != nil {
			slog.Warn("Failed to batch get evidence counts", "error", err)
		}
		attackPaths, err = store.GetAttackPathFlags(ctx, targets)
		if err != nil {
			slog.Warn("Failed to batch get attack path flags", "error", err)
		}
	}

	scored := make([]scoredTarget, len(targets))
	for i, t := range targets {
		var hasOwner, hasAttackPath bool
		var evidenceCount int
		var exploitability int
		var isAuthRequired bool

		if store != nil {
			if assetsMap != nil {
				if asset, ok := assetsMap[t]; ok && asset != nil {
					ao := &ownership.AssetOwnership{
						AssetID: asset.ID,
					}
					if asset.OwnerID != nil {
						ao.OwnerID = *asset.OwnerID
						ao.Confidence = asset.Confidence
					}
					hasOwner = !ao.IsUnmanagedRisk()
				}
			}

			if evidenceCounts != nil {
				evidenceCount = evidenceCounts[t]
			}

			if attackPaths != nil {
				hasAttackPath = attackPaths[t]
			}
		}

		scoreRes := scorer.ScoreEndpointAdvanced(t, isAuthRequired, "", hasOwner, hasAttackPath, evidenceCount, exploitability)
		scored[i] = scoredTarget{target: t, score: scoreRes.Score}
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	targetChan := make(chan string, len(targets))
	for _, st := range scored {
		targetChan <- st.target
	}
	close(targetChan)

	var mu sync.Mutex
	var allEvents []Event

	workersCount := p.workers
	if workersCount > len(targets) {
		workersCount = len(targets)
	}
	if workersCount < 1 {
		workersCount = 1
	}

	for i := 0; i < workersCount; i++ {
		g.Go(func() error {
			for target := range targetChan {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				if p.limiter != nil {
					if err := p.limiter.Wait(ctx); err != nil {
						return err
					}
				}

				events, err := fn(ctx, target)
				if err != nil {
					slog.Debug("target execution error", "target", target, "error", err)
					continue
				}

				if len(events) > 0 {
					mu.Lock()
					allEvents = append(allEvents, events...)
					mu.Unlock()
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return allEvents, nil
}
