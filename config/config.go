package config

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
)

type Config struct {
	Port       string `json:"port" mapstructure:"port"`
	Version    string `json:"version" mapstructure:"version"`
	VendorRoot string `json:"vendor_root" mapstructure:"vendor_root"` // VendorRoot is the key for signing device identity
	RootKey    string `json:"root_key" mapstructure:"root_key"`
	AppName    string `json:"app_name" mapstructure:"app_name"` // AppName is the name of the application
}

var config *Config

func GetConfig() *Config {
	return config
}

func GetVendorRoot() []byte {
	val, _ := hex.DecodeString(strings.TrimPrefix(config.VendorRoot, "0x"))
	return val
}

func GetRootKey() []byte {
	val, _ := hex.DecodeString(strings.TrimPrefix(config.RootKey, "0x"))
	return val
}

func Load(name string) {
	// Open config file
	if name == "" {
		name = "config.json"
	}
	config = &Config{}
	// Load config file
	f, err := os.OpenFile(name, os.O_RDONLY, 0644)
	if err != nil {
		panic(err)
	}
	// Read config file
	fAll, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}
	// Unmarshal config file
	err = json.Unmarshal(fAll, config)
	if err != nil {
		panic(err)
	}
	// Todo: config file sanity check
}
