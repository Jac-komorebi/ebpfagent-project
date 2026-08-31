package redisrepo

// 实现命名空间隔离
const KeyPrefix = "agent:"

// 前缀
func GetRedisKey(key string) string {
	return KeyPrefix + key
}
