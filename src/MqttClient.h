#ifndef MQTT_CLIENT_H
#define MQTT_CLIENT_H

#include <string>
#include <functional>
#include <mosquitto.h>

class MqttClient {
public:
    using MessageCallback = std::function<void(const std::string&)>;

    MqttClient(MessageCallback callback);
    ~MqttClient();

    void connect(const std::string& host, int port, const std::string& username, const std::string& password, const std::string& topic);
    void disconnect();
    void publish(const std::string& topic, const std::string& payload);
    bool is_connected() const;

private:
    static void on_connect_static(struct mosquitto* mosq, void* obj, int rc);
    static void on_message_static(struct mosquitto* mosq, void* obj, const struct mosquitto_message* msg);

    void on_connect(int rc);
    void on_message(const struct mosquitto_message* msg);

    struct mosquitto* mosq;
    MessageCallback on_message_callback;
    bool connected;
    std::string current_topic;
};

#endif // MQTT_CLIENT_H
