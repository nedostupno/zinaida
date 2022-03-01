package config

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type ManagerConfig struct {
	Trace struct {
		DEFAULT_PORT        int `yaml:"default_port"`
		DEFAULT_MAX_HOPS    int `yaml:"default_max_hops"`
		DEFAULT_TIMEOUT_MS  int `yaml:"default_timeout_ms"`
		DEFAULT_RETRIES     int `yaml:"default_retries"`
		DEFAULT_PACKET_SIZE int `yaml:"default_packet_size"`
	} `yaml:"trace"`
	Jwt struct {
		SecretKeyForAccessToken  string `yaml:"secret_key_for_access_token"`
		SecretKeyForRefreshToken string `yaml:"secret_key_for_refresh_token"`
	} `yaml:"jwt"`
	Rest struct {
		Ip   string `yaml:"ip"`
		Port int    `yaml:"port"`
	} `yaml:"rest"`
	Grpc struct {
		Ip   string `yaml:"ip"`
		Port int    `yaml:"port"`
	} `yaml:"gRPC"`
}

func GetManagerConfig() (*ManagerConfig, error) {
	var cfg ManagerConfig
	err := cleanenv.ReadConfig("manager_config.yaml", &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
