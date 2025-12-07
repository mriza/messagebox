#include "MqttClient.h"
#include <iostream>

void MqttClient::on_connect_static(struct mosquitto *mosq, void *obj, int rc) {
  static_cast<MqttClient *>(obj)->on_connect(rc);
}

void MqttClient::on_message_static(struct mosquitto *mosq, void *obj,
                                   const struct mosquitto_message *msg) {
  static_cast<MqttClient *>(obj)->on_message(msg);
}

MqttClient::MqttClient(MessageCallback callback)
    : on_message_callback(callback), connected(false) {
  mosquitto_lib_init();
  mosq = mosquitto_new(nullptr, true, this);
  mosquitto_connect_callback_set(mosq, on_connect_static);
  mosquitto_message_callback_set(mosq, on_message_static);
}

MqttClient::~MqttClient() {
  disconnect();
  mosquitto_destroy(mosq);
  mosquitto_lib_cleanup();
}

void MqttClient::connect(const std::string &host, int port,
                         const std::string &username,
                         const std::string &password,
                         const std::string &topic) {
  if (!username.empty()) {
    mosquitto_username_pw_set(mosq, username.c_str(), password.c_str());
  }
  current_topic = topic;
  int rc = mosquitto_connect(mosq, host.c_str(), port, 60);
  if (rc != MOSQ_ERR_SUCCESS) {
    throw std::runtime_error("Failed to connect to MQTT broker");
  }
  mosquitto_loop_start(mosq);
}

void MqttClient::disconnect() {
  if (connected) {
    mosquitto_disconnect(mosq);
    mosquitto_loop_stop(mosq, true);
    connected = false;
  }
}

void MqttClient::publish(const std::string &topic, const std::string &payload) {
  if (connected) {
    mosquitto_publish(mosq, nullptr, topic.c_str(), payload.length(),
                      payload.c_str(), 0, false);
  }
}

bool MqttClient::is_connected() const { return connected; }

void MqttClient::on_connect(int rc) {
  if (rc == 0) {
    connected = true;
    if (!current_topic.empty()) {
      mosquitto_subscribe(mosq, nullptr, current_topic.c_str(), 0);
    }
  } else {
    connected = false;
  }
}

void MqttClient::on_message(const struct mosquitto_message *msg) {
  std::string payload(static_cast<char *>(msg->payload), msg->payloadlen);
  std::string topic(msg->topic);
  on_message_callback("[MQTT] " + topic + ": " + payload);
}
