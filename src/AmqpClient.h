#ifndef AMQP_CLIENT_H
#define AMQP_CLIENT_H

#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/tcp_socket.h>

class AmqpClient {
public:
    using MessageCallback = std::function<void(const std::string&)>;

    AmqpClient(MessageCallback callback);
    ~AmqpClient();

    void connect(const std::string& host, int port, const std::string& vhost, const std::string& username, const std::string& password, const std::string& queue_name);
    void disconnect();
    void publish(const std::string& exchange, const std::string& routing_key, const std::string& payload);
    void start_consume();
    void stop_consume();
    bool is_connected() const;

private:
    void consume_loop();

    amqp_connection_state_t conn;
    MessageCallback on_message_callback;
    std::atomic<bool> connected;
    std::atomic<bool> consuming;
    std::string current_queue;
    std::thread consume_thread;
};

#endif // AMQP_CLIENT_H
