package main

import (
	"crypto/tls"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type MQTTClient struct {
	client    mqtt.Client
	topic     string
	connected bool
	callback  func(string)
}

func NewMQTTClient(callback func(string)) *MQTTClient {
	return &MQTTClient{callback: callback}
}

func (m *MQTTClient) Connect(host, port, username, password, topic string, useTLS bool) error {
	opts := mqtt.NewClientOptions()
	
	scheme := "tcp"
	if useTLS {
		scheme = "tls"
		opts.SetTLSConfig(&tls.Config{InsecureSkipVerify: true})
	}
	opts.AddBroker(fmt.Sprintf("%s://%s:%s", scheme, host, port))

	if username != "" {
		opts.SetUsername(username)
		opts.SetPassword(password)
	}

	opts.OnConnect = func(c mqtt.Client) {
		m.connected = true
		if topic != "" {
			c.Subscribe(topic, 0, m.onMessage)
		}
	}
	opts.OnConnectionLost = func(c mqtt.Client, err error) {
		m.connected = false
	}

	m.client = mqtt.NewClient(opts)
	m.topic = topic

	token := m.client.Connect()
	if token.Wait() && token.Error() != nil {
		return token.Error()
	}

	return nil
}

func (m *MQTTClient) onMessage(client mqtt.Client, msg mqtt.Message) {
	if m.callback != nil {
		m.callback(fmt.Sprintf("[MQTT] %s: %s", msg.Topic(), string(msg.Payload())))
	}
}

func (m *MQTTClient) Publish(topic, payload string) error {
	if m.client != nil && m.client.IsConnected() {
		token := m.client.Publish(topic, 0, false, payload)
		token.Wait()
		return token.Error()
	}
	return fmt.Errorf("not connected")
}

func (m *MQTTClient) Disconnect() {
	if m.client != nil && m.client.IsConnected() {
		m.client.Disconnect(250)
		m.connected = false
	}
}
