package redisrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/settings"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
	"github.com/redis/go-redis/v9"
)

// 多实例部署使用
type Redisrepo struct {
	client *redis.Client
}

// redis连接
func New(cfg *settings.RedisConfig) (*Redisrepo, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Passwd,
		DB:       cfg.DB,
	})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Redisrepo{client: client}, nil
}

// agentID+PID组合键
func keyName(agentID string, pid uint32) string {
	return fmt.Sprintf("%sagent:%s:pid:%d", KeyPrefix, agentID, pid)
}

// 存储、更新状态
func (r *Redisrepo) Isolation(ctx context.Context, agentID string, pid uint32, prompt string, state int) error {
	key := keyName(agentID, pid)
	repo := &solution.AgentRepository{
		Prompt:         prompt,
		State:          state,
		LastActiveTime: time.Now(),
	}
	data, err := json.Marshal(repo)
	if err != nil {
		return fmt.Errorf("marshal repo: %w", err)
	}
	return r.client.Set(ctx, key, data, 0).Err()
}

// 获取状态
func (r *Redisrepo) Get(ctx context.Context, agentID string, pid uint32) (*solution.AgentRepository, error) {
	key := keyName(agentID, pid)
	data, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis get: %w", err)
	}
	var repo solution.AgentRepository
	if err := json.Unmarshal(data, &repo); err != nil {
		return nil, fmt.Errorf("unmarshal repo: %w", err)
	}
	return &repo, nil
}

// 删除
func (r *Redisrepo) Delete(ctx context.Context, agentID string, pid uint32) error {
	key := keyName(agentID, pid)
	return r.client.Del(ctx, key).Err()
}

// 关闭(不依赖context直接释放资源)
func (r *Redisrepo) Close() error {
	return r.client.Close()
}

// 关闭(实现业务接口（AgentMapper）的适配器)
func (r *Redisrepo) Shutdown(_ context.Context) error {
	return r.client.Close()
}
