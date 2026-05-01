package web

import (
	"context"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

type ctxKey struct{}

type queryStats struct {
	count   atomic.Int64
	totalNs atomic.Int64
}

func (qs *queryStats) record(d time.Duration) {
	qs.count.Add(1)
	qs.totalNs.Add(d.Nanoseconds())
}

func (qs *queryStats) Count() int64            { return qs.count.Load() }
func (qs *queryStats) Duration() time.Duration { return time.Duration(qs.totalNs.Load()) }

func contextWithStats(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, &queryStats{})
}

func statsFromContext(ctx context.Context) *queryStats {
	qs, _ := ctx.Value(ctxKey{}).(*queryStats)
	return qs
}

var startTimeKey = "web:start"

func registerQueryStatsCallback(gdb *gorm.DB) error {
	cb := gdb.Callback()
	regs := []error{
		cb.Query().Before("gorm:query").Register("web:before_query", stampStart),
		cb.Query().After("gorm:query").Register("web:after_query", recordElapsed),
		cb.Create().Before("gorm:create").Register("web:before_create", stampStart),
		cb.Create().After("gorm:create").Register("web:after_create", recordElapsed),
		cb.Update().Before("gorm:update").Register("web:before_update", stampStart),
		cb.Update().After("gorm:update").Register("web:after_update", recordElapsed),
		cb.Delete().Before("gorm:delete").Register("web:before_delete", stampStart),
		cb.Delete().After("gorm:delete").Register("web:after_delete", recordElapsed),
		cb.Raw().Before("gorm:raw").Register("web:before_raw", stampStart),
		cb.Raw().After("gorm:raw").Register("web:after_raw", recordElapsed),
		cb.Row().Before("gorm:row").Register("web:before_row", stampStart),
		cb.Row().After("gorm:row").Register("web:after_row", recordElapsed),
	}
	for _, err := range regs {
		if err != nil {
			return err
		}
	}
	return nil
}

func stampStart(gdb *gorm.DB) {
	if gdb.Statement == nil {
		return
	}
	if statsFromContext(gdb.Statement.Context) == nil {
		return
	}
	gdb.Statement.Settings.Store(startTimeKey, time.Now())
}

func recordElapsed(gdb *gorm.DB) {
	if gdb.Statement == nil {
		return
	}
	qs := statsFromContext(gdb.Statement.Context)
	if qs == nil {
		return
	}
	v, ok := gdb.Statement.Settings.Load(startTimeKey)
	if !ok {
		return
	}
	qs.record(time.Since(v.(time.Time)))
}
