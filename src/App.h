#ifndef APP_H
#define APP_H

#include "AmqpClient.h"
#include "MqttClient.h"
#include "ProfileManager.h"
#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMessageBox>
#include <QMetaObject>
#include <QPushButton>
#include <QStackedWidget>
#include <QString>
#include <QTextEdit>
#include <QThread>
#include <QVBoxLayout>
#include <QWidget>
#include <memory>

class App : public QMainWindow {
  Q_OBJECT

public:
  App(QWidget *parent = nullptr);
  ~App();

public slots:
  void append_log(const QString &text);

private slots:
  void on_connect_clicked();
  void on_send_clicked();
  void on_protocol_changed(const QString &text);
  void on_load_profile();
  void on_save_profile();
  void on_delete_profile();
  void on_receiver_toggled(bool checked);
  void update_ui_state();

private:
  void init_ui();
  void load_profile_list();
  void connect_clients();
  void disconnect_clients();

  // UI Elements
  QComboBox *combo_profiles;
  QComboBox *combo_protocol;
  QLineEdit *entry_host;
  QLineEdit *entry_port;
  QLineEdit *entry_user;
  QLineEdit *entry_pass;

  QStackedWidget *stack_proto;
  QWidget *page_mqtt;
  QLineEdit *entry_mqtt_topic;

  QWidget *page_amqp;
  QLineEdit *entry_amqp_vhost;
  QLineEdit *entry_amqp_queue;
  QLineEdit *entry_amqp_exchange;
  QLineEdit *entry_amqp_routing;

  QPushButton *btn_connect;

  // Sender
  QCheckBox *chk_sender;
  QLineEdit *entry_payload;
  QPushButton *btn_send;
  QTextEdit *txt_sent_log;

  // Receiver
  QCheckBox *chk_receiver;
  QTextEdit *txt_received_log;

  // Logic
  ProfileManager profile_manager;
  std::unique_ptr<MqttClient> mqtt_client;
  std::unique_ptr<AmqpClient> amqp_client;
  bool connected = false;
};

#endif // APP_H
