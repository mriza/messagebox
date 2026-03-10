package main

import (
	"crypto/tls"
	"fmt"
	"strings"

	amqp "github.com/rabbitmq/amqp091-go"
)

type AMQPClient struct {
	conn     *amqp.Connection
	ch       *amqp.Channel
	queue    string
	callback func(string)
	stopChan chan struct{}
}

func NewAMQPClient(callback func(string)) *AMQPClient {
	return &AMQPClient{callback: callback}
}

func (a *AMQPClient) Connect(amqpUrl, queue string) error {
	config := amqp.Config{
		Properties: amqp.NewConnectionProperties(),
	}
	
	if strings.HasPrefix(amqpUrl, "amqps://") {
		config.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	conn, err := amqp.DialConfig(amqpUrl, config)
	if err != nil {
		return err
	}
	a.conn = conn

	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	a.ch = ch
	a.queue = queue

	_, err = ch.QueueDeclare(
		queue,
		false,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return err
	}

	return nil
}

func (a *AMQPClient) StartConsume() error {
	if a.ch == nil {
		return fmt.Errorf("channel not initialized")
	}

	msgs, err := a.ch.Consume(
		a.queue,
		"",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return err
	}

	a.stopChan = make(chan struct{})

	go func() {
		for {
			select {
			case d, ok := <-msgs:
				if !ok {
					return
				}
				if a.callback != nil {
					a.callback(fmt.Sprintf("[AMQP] %s: %s", a.queue, string(d.Body)))
				}
			case <-a.stopChan:
				return
			}
		}
	}()

	return nil
}

func (a *AMQPClient) StopConsume() {
	if a.stopChan != nil {
		close(a.stopChan)
		a.stopChan = nil
	}
}

func (a *AMQPClient) Publish(exchange, routingKey, payload string) error {
	if a.ch == nil {
		return fmt.Errorf("channel not initialized")
	}

	return a.ch.Publish(
		exchange,
		routingKey,
		false,
		false,
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(payload),
		},
	)
}

func (a *AMQPClient) Disconnect() {
	a.StopConsume()
	if a.ch != nil && !a.ch.IsClosed() {
		a.ch.Close()
	}
	if a.conn != nil && !a.conn.IsClosed() {
		a.conn.Close()
	}
}
