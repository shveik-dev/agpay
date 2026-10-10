package app

import (
	"context"
	"encoding/json"
	"time"
)

func contextTimeout(c *ctx, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Ctx, d)
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
