package main

import (
	"context"
	"fmt"
	"path/filepath"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx   context.Context
	pm    *ProfileManager
	mqtt  *MQTTClient
	amqp  *AMQPClient
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	exePath, _ := os.Executable()
	profilePath := filepath.Join(filepath.Dir(exePath), "profiles.txt")
	
	a.pm = NewProfileManager(profilePath)
	
	callback := func(msg string) {
		runtime.EventsEmit(ctx, "log", msg)
	}
	
	a.mqtt = NewMQTTClient(callback)
	a.amqp = NewAMQPClient(callback)
}

// Profile Management
func (a *App) GetProfiles() map[string]Profile {
	if a.pm == nil {
		return make(map[string]Profile)
	}
	return a.pm.GetAll()
}

func (a *App) SaveProfile(name string, profile Profile) error {
	return a.pm.Save(name, profile)
}

func (a *App) DeleteProfile(name string) error {
	return a.pm.Delete(name)
}

// MQTT Let's expose connection methods
func (a *App) ConnectMQTT(host, port, username, password, topic string, useTLS bool) error {
	return a.mqtt.Connect(host, port, username, password, topic, useTLS)
}

func (a *App) PublishMQTT(topic, payload string) error {
	err := a.mqtt.Publish(topic, payload)
	if err == nil {
		runtime.EventsEmit(a.ctx, "log", fmt.Sprintf("[MQTT-SENT] %s", payload))
	}
	return err
}

func (a *App) DisconnectMQTT() {
	if a.mqtt != nil {
		a.mqtt.Disconnect()
	}
}

// AMQP Expose connection methods
func (a *App) ConnectAMQP(amqpUrl, queue string) error {
	return a.amqp.Connect(amqpUrl, queue)
}

func (a *App) StartConsumeAMQP() error {
	return a.amqp.StartConsume()
}

func (a *App) StopConsumeAMQP() {
	if a.amqp != nil {
		a.amqp.StopConsume()
	}
}

func (a *App) PublishAMQP(exchange, routingKey, payload string) error {
	err := a.amqp.Publish(exchange, routingKey, payload)
	if err == nil {
		runtime.EventsEmit(a.ctx, "log", fmt.Sprintf("[AMQP-SENT] %s", payload))
	}
	return err
}

func (a *App) DisconnectAMQP() {
	if a.amqp != nil {
		a.amqp.Disconnect()
	}
}
