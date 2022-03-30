package config

import (
	"fmt"
	"net"
	"regexp"
	"unicode/utf8"

	"github.com/ilyakaznacheev/cleanenv"
)

type ManagerConfig struct {
	Trace struct {
		Port        int `yaml:"port" env-default:"5432"`
		Max_hops    int `yaml:"max_hops" env-default:"15"`
		Timeout_ms  int `yaml:"timeout_ms" env-default:"500"`
		Retries     int `yaml:"retries" env-default:"3"`
		Packet_size int `yaml:"packet_size" env-default:"52"`
	} `yaml:"trace"`
	Jwt struct {
		SecretKeyForAccessToken  string `yaml:"secret_key_for_access_token" env-required:"true"`
		SecretKeyForRefreshToken string `yaml:"secret_key_for_refresh_token" env-required:"true"`
		AccessTokenTTL           int    `yaml:"access_token_ttl" env-default:"15"`
		RefreshTokenTTL          int    `yaml:"refresh_token_ttl" env-default:"300"`
	} `yaml:"jwt"`
	Rest struct {
		Ip   string `yaml:"ip" env-default:"0.0.0.0"`
		Port int    `yaml:"port" env-default:"8000"`
	} `yaml:"rest"`
	Grpc struct {
		Ip          string `yaml:"ip" env-default:"0.0.0.0"`
		Port        int    `yaml:"port" env-default:"42222"`
		AgentsPort  int    `yaml:"agents_port" env-default:"24444"`
		PingTimeout int    `yaml:"ping_timeout" env-default:"5"`
	} `yaml:"gRPC"`
}

type AgentConfig struct {
	Manager struct {
		Ip   string `yaml:"ip" env-required:"true"`
		Port int    `yaml:"port" env-default:"42222"`
	} `yaml:"manager"`
	Agent struct {
		Ip     string `yaml:"ip" env-default:"0.0.0.0"`
		Port   int    `yaml:"port" env-default:"24444"`
		Domain string `yaml:"domain"`
	} `yaml:"agent"`
}

func GetManagerConfig() (*ManagerConfig, error) {
	var cfg ManagerConfig
	err := cleanenv.ReadConfig("manager_config.yaml", &cfg)
	if err != nil {
		return nil, err
	}

	if r := net.ParseIP(cfg.Rest.Ip); r == nil {
		return nil, fmt.Errorf("в manager_config.yaml для rest указан не валидный ip адрес")
	}
	if r := net.ParseIP(cfg.Grpc.Ip); r == nil {
		return nil, fmt.Errorf("в manager_config.yaml для grpc указан не валидный ip адрес")
	}
	return &cfg, nil
}

func GetAgentConfig() (*AgentConfig, error) {
	var cfg AgentConfig
	err := cleanenv.ReadConfig("agent_config.yaml", &cfg)
	if err != nil {
		return nil, err
	}

	if r := net.ParseIP(cfg.Agent.Ip); r == nil {
		return nil, fmt.Errorf("в agent_config.yaml для agent указан не валидный ip адрес")
	}

	if r := net.ParseIP(cfg.Manager.Ip); r == nil {
		return nil, fmt.Errorf("в agent_config.yaml для manager указан не валидный ip адрес")
	}

	reg, err := regexp.Compile(`^([A-Za-zА-Яа-я0-9-]{1,63}\.)+[A-Za-zА-Яа-я0-9]{2,6}$`)
	if err != nil {
		return nil, fmt.Errorf("не удалось скомпилировать регулярное выражение")
	}
	ok := reg.MatchString(cfg.Agent.Domain)
	if !ok {
		return nil, fmt.Errorf("в agent_config.yaml для agent указан не валидный домен")
	}
	len := utf8.RuneCountInString(cfg.Agent.Domain)
	if len > 253 {
		return nil, fmt.Errorf("в agent_config.yaml для agent указан не валидный домен")
	}
	return &cfg, nil
}
