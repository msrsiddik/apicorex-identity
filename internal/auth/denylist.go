package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// Denylist writes revoked access-token JTIs to Redis on logout. Core reads it.
type Denylist struct {
	rdb *redis.Client
}

func NewDenylist(redisURL string) (*Denylist, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	return &Denylist{rdb: redis.NewClient(opt)}, nil
}

// Revoke adds a JTI to the denylist with a TTL equal to its remaining lifetime.
func (d *Denylist) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	if d == nil || jti == "" || ttl <= 0 {
		return nil
	}
	return d.rdb.Set(ctx, "denylist:jti:"+jti, "1", ttl).Err()
}
