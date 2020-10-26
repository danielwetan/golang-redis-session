package helpers

import (
	"github.com/gomodule/redigo/redis"
)

func InitCache() redis.Conn {
	// Initialize the redis connection to a redis intance running on local machine
	conn, err := redis.DialURL("redis://localhost")
	if err != nil {
		panic(err)
	}
	cache := conn
	return cache
}
