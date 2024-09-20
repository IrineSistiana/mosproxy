package cache

type Times struct {
	StoredAtUnix      int64 // Info only
	ExpireAtUnix      int64 // Info only
	CacheExpireAtUnix int64
}

