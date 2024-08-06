package storage

const config = "config.json"

type Config struct {
	DefaultKey string `json:"defaultKey"`
}

func GetConfig() Config {
	return Config{}
}
