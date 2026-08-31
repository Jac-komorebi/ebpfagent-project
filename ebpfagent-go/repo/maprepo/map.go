package maprepo

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

const numShards = 16

// 单个分片，独立锁避免全局停顿
type shard struct {
	mu   sync.RWMutex
	data map[string]*solution.AgentRepository
}

// 单实例部署，分片锁降低竞争
type Maprepo struct {
	shards [numShards]*shard
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// 过期条目清理
func New() *Maprepo {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Maprepo{
		ctx:    ctx,
		cancel: cancel,
	}
	for i := range m.shards {
		m.shards[i] = &shard{data: make(map[string]*solution.AgentRepository)}
	}
	m.wg.Add(1)
	go m.cleanupLoop(10 * time.Minute)
	return m
}

// 组合agentID和PID为存储键
func buildKey(agentID string, pid uint32) string {
	return fmt.Sprintf("agent:%s:pid:%d", agentID, pid)
}

// 哈希选择分片
func (m *Maprepo) getShard(key string) *shard {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return m.shards[h%numShards]
}

func (m *Maprepo) Isolation(_ context.Context, agentID string, pid uint32, prompt string, state int) error {
	key := buildKey(agentID, pid)
	s := m.getShard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	repo, exists := s.data[key]
	if !exists {
		repo = &solution.AgentRepository{}
		s.data[key] = repo
	}
	repo.Prompt = prompt
	repo.State = state
	repo.LastActiveTime = time.Now()
	return nil
}

// 获取
func (m *Maprepo) Get(_ context.Context, agentID string, pid uint32) (*solution.AgentRepository, error) {
	key := buildKey(agentID, pid)
	s := m.getShard(key)
	s.mu.RLock()
	defer s.mu.RUnlock()

	repo, exists := s.data[key]
	if !exists {
		return nil, nil
	}
	return repo, nil
}

// 删除，防止oom
func (m *Maprepo) Delete(_ context.Context, agentID string, pid uint32) error {
	key := buildKey(agentID, pid)
	s := m.getShard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)
	return nil
}

// 关闭
func (m *Maprepo) Shutdown(_ context.Context) error {
	m.cancel()
	m.wg.Wait()
	return nil
}

// 分批逐分片清理，释放锁间隙避免长时间停顿
func (m *Maprepo) cleanupLoop(interval time.Duration) {
	defer m.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanExpired()
		}
	}
}

func (m *Maprepo) cleanExpired() {
	deadline := time.Now().Add(-15 * time.Minute)
	for _, s := range m.shards {
		// 先收集过期键，避免在持锁期间删除
		var expired []string
		s.mu.RLock()
		for key, repo := range s.data {
			if repo.LastActiveTime.Before(deadline) {
				expired = append(expired, key)
			}
		}
		s.mu.RUnlock()

		if len(expired) == 0 {
			continue
		}

		s.mu.Lock()
		for _, key := range expired {
			// 二次确认，防止在RUnlock到Lock间隙中被重新激活
			if repo, ok := s.data[key]; ok && repo.LastActiveTime.Before(deadline) {
				delete(s.data, key)
			}
		}
		s.mu.Unlock()

		select {
		case <-m.ctx.Done():
			return
		default:
		}
	}
}
