package config

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type ManagerConfig struct {
	Trace struct {
		Port        int `yaml:"port"`
		Max_hops    int `yaml:"max_hops"`
		Timeout_ms  int `yaml:"timeout_ms"`
		Retries     int `yaml:"retries"`
		Packet_size int `yaml:"packet_size"`
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
