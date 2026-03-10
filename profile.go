package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"sync"
)

type Profile struct {
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	Host         string `json:"host"`
	Port         string `json:"port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	MqttTopic    string `json:"mqtt_topic"`
	AmqpVHost    string `json:"amqp_vhost"`
	AmqpQueue    string `json:"amqp_queue"`
	AmqpExchange string `json:"amqp_exchange"`
	AmqpRouting  string `json:"amqp_routing"`
	UseTLS       bool   `json:"use_tls"`
	AmqpURL      string `json:"amqp_url"`
}

type ProfileManager struct {
	FilePath string
	Profiles map[string]Profile
	mu       sync.RWMutex
}

func NewProfileManager(filepath string) *ProfileManager {
	pm := &ProfileManager{
		FilePath: filepath,
		Profiles: make(map[string]Profile),
	}
	pm.LoadAll()
	return pm
}

func (pm *ProfileManager) LoadAll() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	data, err := os.ReadFile(pm.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // OK if file doesn't exist
		}
		return err
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil
	}

	// Fix padding if necessary
	if missingPadding := len(content) % 4; missingPadding != 0 {
		content += strings.Repeat("=", 4-missingPadding)
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return err // Return empty essentially, or log err
	}

	err = json.Unmarshal(decodedBytes, &pm.Profiles)
	if err != nil {
		return err
	}

	return nil
}

func (pm *ProfileManager) SaveAll() error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	jsonBytes, err := json.Marshal(pm.Profiles)
	if err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(jsonBytes)
	return os.WriteFile(pm.FilePath, []byte(encoded), 0644)
}

func (pm *ProfileManager) Save(name string, profile Profile) error {
	pm.mu.Lock()
	profile.Name = name
	pm.Profiles[name] = profile
	pm.mu.Unlock()
	return pm.SaveAll()
}

func (pm *ProfileManager) Delete(name string) error {
	pm.mu.Lock()
	delete(pm.Profiles, name)
	pm.mu.Unlock()
	return pm.SaveAll()
}

func (pm *ProfileManager) GetAll() map[string]Profile {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Return a copy to be safe
	copyData := make(map[string]Profile)
	for k, v := range pm.Profiles {
		copyData[k] = v
	}
	return copyData
}
