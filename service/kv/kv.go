package kv

import "sync"

type Entry struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Provisioner string `json:"provisioner"`
	Protector   string `json:"protector"`
}

var entries = sync.Map{}

func Exists(key string) bool {
	_, ok := entries.Load(key)
	return ok
}

func Load(key string) (Entry, bool) {
	if value, ok := entries.Load(key); ok {
		return value.(Entry), true
	}
	return Entry{}, false
}

func Store(entry Entry) {
	entries.Store(entry.Key, entry)
}

func Length() int {
	length := 0
	entries.Range(func(_, _ interface{}) bool {
		length++
		return true
	})
	return length
}

func Delete(key string) {
	entries.Delete(key)
}
