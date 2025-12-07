#include "AmqpClient.h"
#include <chrono>
#include <iostream>
#include <stdexcept>

AmqpClient::AmqpClient(MessageCallback callback)
    : conn(nullptr), on_message_callback(callback), connected(false),
      consuming(false) {}

AmqpClient::~AmqpClient() { disconnect(); }

void AmqpClient::connect(const std::string &host, int port,
                         const std::string &vhost, const std::string &username,
                         const std::string &password,
                         const std::string &queue_name) {
  conn = amqp_new_connection();
  amqp_socket_t *socket = amqp_tcp_socket_new(conn);
  if (!socket) {
    throw std::runtime_error("Creating TCP socket failed");
  }

  if (amqp_socket_open(socket, host.c_str(), port)) {
    throw std::runtime_error("Opening TCP socket failed");
  }

  amqp_rpc_reply_t login_reply =
      amqp_login(conn, vhost.c_str(), 0, 131072, 0, AMQP_SASL_METHOD_PLAIN,
                 username.c_str(), password.c_str());
  if (login_reply.reply_type != AMQP_RESPONSE_NORMAL) {
    throw std::runtime_error("AMQP Login failed");
  }

  amqp_channel_open(conn, 1);
  amqp_get_rpc_reply(conn);

  current_queue = queue_name;

  // Declare queue (passive=0, durable=0, exclusive=0, auto_delete=0) -> simple
  // default
  amqp_queue_declare(conn, 1, amqp_cstring_bytes(queue_name.c_str()), 0, 0, 0,
                     0, amqp_empty_table);
  amqp_get_rpc_reply(conn);

  connected = true;
}

void AmqpClient::disconnect() {
  stop_consume();
  if (connected) {
    amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS);
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
    connected = false;
  }
}

void AmqpClient::publish(const std::string &exchange,
                         const std::string &routing_key,
                         const std::string &payload) {
  if (!connected)
    return;

  amqp_basic_properties_t props;
  props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
  props.content_type = amqp_cstring_bytes("text/plain");
  props.delivery_mode = 2; // persistent

  amqp_basic_publish(conn, 1, amqp_cstring_bytes(exchange.c_str()),
                     amqp_cstring_bytes(routing_key.c_str()), 0, 0, &props,
                     amqp_cstring_bytes(payload.c_str()));
}

void AmqpClient::start_consume() {
  if (!connected || consuming)
    return;

  amqp_basic_consume(conn, 1, amqp_cstring_bytes(current_queue.c_str()),
                     amqp_empty_bytes, 0, 0, 0, amqp_empty_table);
  amqp_get_rpc_reply(conn);

  consuming = true;
  consume_thread = std::thread(&AmqpClient::consume_loop, this);
}

void AmqpClient::stop_consume() {
  consuming = false;
  if (consume_thread.joinable()) {
    consume_thread.join();
  }
}

void AmqpClient::consume_loop() {
  while (consuming && connected) {
    amqp_rpc_reply_t res;
    amqp_envelope_t envelope;

    amqp_maybe_release_buffers(conn);
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    res = amqp_consume_message(conn, &envelope, &timeout, 0);

    if (AMQP_RESPONSE_NORMAL == res.reply_type) {
      std::string payload((char *)envelope.message.body.bytes,
                          envelope.message.body.len);
      std::string routing_key((char *)envelope.routing_key.bytes,
                              envelope.routing_key.len);

      on_message_callback("[AMQP] " + routing_key + ": " + payload);

      amqp_destroy_envelope(&envelope);
    }
  }
}

bool AmqpClient::is_connected() const { return connected; }
