package api

import (
	"sync"
	"time"
)

const (
	// rateWindow 是固定窗口长度。
	rateWindow = time.Minute
	// rateLimit 是每个 key 在窗口内允许的请求数。
	rateLimit = 60
	// rateMaxBuckets 是内存中保留的最大计数桶数，超过时清理过期项。
	rateMaxBuckets = 4096
)

// rateLimiter 是进程内固定窗口限流器（按 key 计数）。
//
// 并发契约：允许计数读写在互斥锁保护下进行；时间来源由调用方注入（见 ASYNC.md）。
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
}

// rateBucket 是单个 key 的计数窗口。
type rateBucket struct {
	count int
	reset time.Time
}

// newRateLimiter 创建限流器。
func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*rateBucket)}
}

// allow 判断 key 当前是否允许通过；不允许时返回建议的 Retry-After 秒数。
func (rl *rateLimiter) allow(key string, now time.Time) (bool, int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if len(rl.buckets) > rateMaxBuckets {
		rl.pruneLocked(now)
	}
	b, ok := rl.buckets[key]
	if !ok || now.After(b.reset) {
		rl.buckets[key] = &rateBucket{count: 1, reset: now.Add(rateWindow)}
		return true, 0
	}
	if b.count >= rateLimit {
		secs := int64(b.reset.Sub(now).Seconds())
		if secs < 1 {
			secs = 1
		}
		return false, secs
	}
	b.count++
	return true, 0
}

// pruneLocked 清理已过期的计数桶（调用方必须持锁）。
func (rl *rateLimiter) pruneLocked(now time.Time) {
	for k, b := range rl.buckets {
		if now.After(b.reset) {
			delete(rl.buckets, k)
		}
	}
}
