#include "App.h"
#include <QStyleFactory>

App::App(QWidget *parent)
    : QMainWindow(parent), profile_manager("profiles.txt") {
  setWindowTitle("MessageBox : An MQTT & AMQP Tester");
  resize(800, 600);

  init_ui();

  // Initialize logic
  mqtt_client = std::make_unique<MqttClient>([this](const std::string &msg) {
    QMetaObject::invokeMethod(this, "append_log", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(msg)));
  });

  amqp_client = std::make_unique<AmqpClient>([this](const std::string &msg) {
    QMetaObject::invokeMethod(this, "append_log", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(msg)));
  });
}

App::~App() {
  if (connected)
    disconnect_clients();
}

void App::init_ui() {
  QWidget *central = new QWidget;
  setCentralWidget(central);
  QVBoxLayout *main_layout = new QVBoxLayout(central);

  // === Profiles ===
  QGroupBox *grp_profiles = new QGroupBox("Profiles");
  QHBoxLayout *lay_profiles = new QHBoxLayout;
  combo_profiles = new QComboBox;
  combo_profiles->setMinimumWidth(200);
  QPushButton *btn_load = new QPushButton("Load");
  QPushButton *btn_save = new QPushButton("Save");
  QPushButton *btn_del = new QPushButton("Delete");

  lay_profiles->addWidget(combo_profiles);
  lay_profiles->addWidget(btn_load);
  lay_profiles->addWidget(btn_save);
  lay_profiles->addWidget(btn_del);
  lay_profiles->addStretch();
  grp_profiles->setLayout(lay_profiles);
  main_layout->addWidget(grp_profiles);

  connect(btn_load, &QPushButton::clicked, this, &App::on_load_profile);
  connect(btn_save, &QPushButton::clicked, this, &App::on_save_profile);
  connect(btn_del, &QPushButton::clicked, this, &App::on_delete_profile);

  load_profile_list();

  // === Connection Settings ===
  QGroupBox *grp_conn = new QGroupBox("Connection Settings");
  QFormLayout *lay_conn = new QFormLayout;

  combo_protocol = new QComboBox;
  combo_protocol->addItems({"MQTT", "AMQP"});
  lay_conn->addRow("Protocol:", combo_protocol);
  connect(combo_protocol, &QComboBox::currentTextChanged, this,
          &App::on_protocol_changed);

  QHBoxLayout *lay_host = new QHBoxLayout;
  entry_host = new QLineEdit("localhost");
  entry_port = new QLineEdit("1883");
  entry_port->setFixedWidth(80);
  lay_host->addWidget(entry_host);
  lay_host->addWidget(new QLabel("Port:"));
  lay_host->addWidget(entry_port);
  lay_conn->addRow("Host:", lay_host);

  QHBoxLayout *lay_auth = new QHBoxLayout;
  entry_user = new QLineEdit;
  entry_pass = new QLineEdit;
  entry_pass->setEchoMode(QLineEdit::Password);
  lay_auth->addWidget(entry_user);
  lay_auth->addWidget(new QLabel("Password:"));
  lay_auth->addWidget(entry_pass);
  lay_conn->addRow("Username:", lay_auth);

  stack_proto = new QStackedWidget;

  // MQTT Page
  page_mqtt = new QWidget;
  QFormLayout *lay_mqtt = new QFormLayout(page_mqtt);
  lay_mqtt->setContentsMargins(0, 0, 0, 0);
  entry_mqtt_topic = new QLineEdit("test/topic");
  lay_mqtt->addRow("MQTT Topic:", entry_mqtt_topic);
  stack_proto->addWidget(page_mqtt);

  // AMQP Page
  page_amqp = new QWidget;
  QFormLayout *lay_amqp = new QFormLayout(page_amqp);
  lay_amqp->setContentsMargins(0, 0, 0, 0);
  entry_amqp_vhost = new QLineEdit("/");
  entry_amqp_queue = new QLineEdit("test_queue");
  entry_amqp_exchange = new QLineEdit;
  entry_amqp_routing = new QLineEdit("test_queue");

  QHBoxLayout *lay_amqp1 = new QHBoxLayout;
  lay_amqp1->addWidget(entry_amqp_vhost);
  lay_amqp1->addWidget(new QLabel("Queue:"));
  lay_amqp1->addWidget(entry_amqp_queue);

  QHBoxLayout *lay_amqp2 = new QHBoxLayout;
  lay_amqp2->addWidget(entry_amqp_exchange);
  lay_amqp2->addWidget(new QLabel("Routing:"));
  lay_amqp2->addWidget(entry_amqp_routing);

  lay_amqp->addRow("VHost:", lay_amqp1);
  lay_amqp->addRow("Exchange:", lay_amqp2);
  stack_proto->addWidget(page_amqp);

  lay_conn->addRow(stack_proto);

  btn_connect = new QPushButton("Connect");
  QHBoxLayout *lay_btn_conn = new QHBoxLayout;
  lay_btn_conn->addStretch();
  lay_btn_conn->addWidget(btn_connect);
  lay_conn->addRow(lay_btn_conn);

  connect(btn_connect, &QPushButton::clicked, this, &App::on_connect_clicked);

  grp_conn->setLayout(lay_conn);
  main_layout->addWidget(grp_conn);

  // === Bottom Section ===
  QHBoxLayout *lay_bottom = new QHBoxLayout;

  // === Sender ===
  QGroupBox *grp_send = new QGroupBox("Sender");
  QVBoxLayout *lay_send = new QVBoxLayout;
  chk_sender = new QCheckBox("Enable Sender");
  chk_sender->setChecked(true);
  lay_send->addWidget(chk_sender);

  QHBoxLayout *lay_payload = new QHBoxLayout;
  entry_payload = new QLineEdit;
  btn_send = new QPushButton("Send");
  lay_payload->addWidget(new QLabel("Payload:"));
  lay_payload->addWidget(entry_payload);
  lay_payload->addWidget(btn_send);
  lay_send->addLayout(lay_payload);

  txt_sent_log = new QTextEdit;
  txt_sent_log->setReadOnly(true);
  lay_send->addWidget(txt_sent_log);

  // lay_send->addStretch(); // commented out to let log expand

  grp_send->setLayout(lay_send);
  lay_bottom->addWidget(grp_send, 1);

  connect(chk_sender, &QCheckBox::toggled, this, &App::update_ui_state);
  connect(btn_send, &QPushButton::clicked, this, &App::on_send_clicked);

  // === Receiver ===
  QGroupBox *grp_recv = new QGroupBox("Receiver");
  QVBoxLayout *lay_recv = new QVBoxLayout;
  chk_receiver = new QCheckBox("Enable Receiver");
  chk_receiver->setChecked(true);
  lay_recv->addWidget(chk_receiver);

  lay_recv->addWidget(chk_receiver);

  txt_received_log = new QTextEdit;
  txt_received_log->setReadOnly(true);
  lay_recv->addWidget(txt_received_log);

  grp_recv->setLayout(lay_recv);
  lay_bottom->addWidget(grp_recv, 1);

  main_layout->addLayout(lay_bottom);

  connect(chk_receiver, &QCheckBox::toggled, this, &App::on_receiver_toggled);

  update_ui_state();
}

void App::append_log(const QString &text) {
  if (text.startsWith("[SEND]") || text.contains("Published")) {
    txt_sent_log->append(text);
  } else {
    txt_received_log->append(text);
  }
}

void App::on_protocol_changed(const QString &text) {
  if (text == "MQTT") {
    stack_proto->setCurrentWidget(page_mqtt);
    if (entry_port->text() == "5672" || entry_port->text().isEmpty())
      entry_port->setText("1883");
  } else {
    stack_proto->setCurrentWidget(page_amqp);
    if (entry_port->text() == "1883" || entry_port->text().isEmpty())
      entry_port->setText("5672");
  }
}

void App::update_ui_state() {
  bool send_ok = connected && chk_sender->isChecked();
  entry_payload->setEnabled(send_ok);
  btn_send->setEnabled(send_ok);

  chk_sender->setEnabled(connected);
  chk_receiver->setEnabled(connected);
}

void App::on_connect_clicked() {
  if (connected) {
    disconnect_clients();
  } else {
    connect_clients();
  }
}

void App::connect_clients() {
  try {
    QString host = entry_host->text();
    int port = entry_port->text().toInt();
    QString user = entry_user->text();
    QString pass = entry_pass->text();
    QString proto = combo_protocol->currentText();

    if (proto == "MQTT") {
      mqtt_client->connect(host.toStdString(), port, user.toStdString(),
                           pass.toStdString(),
                           entry_mqtt_topic->text().toStdString());
    } else {
      amqp_client->connect(host.toStdString(), port,
                           entry_amqp_vhost->text().toStdString(),
                           user.toStdString(), pass.toStdString(),
                           entry_amqp_queue->text().toStdString());
    }

    connected = true;
    btn_connect->setText("Disconnect");
    append_log("Connected to " + proto);
    update_ui_state();

    if (chk_receiver->isChecked() && proto == "AMQP") {
      amqp_client->start_consume();
    }

  } catch (const std::exception &e) {
    QMessageBox::critical(this, "Connection Error", e.what());
  }
}

void App::disconnect_clients() {
  QString proto = combo_protocol->currentText();
  if (proto == "MQTT")
    mqtt_client->disconnect();
  else
    amqp_client->disconnect();

  connected = false;
  btn_connect->setText("Connect");
  append_log("Disconnected.");
  update_ui_state();
}

void App::on_send_clicked() {
  if (!connected)
    return;
  QString payload = entry_payload->text();
  QString proto = combo_protocol->currentText();

  if (proto == "MQTT") {
    mqtt_client->publish(entry_mqtt_topic->text().toStdString(),
                         payload.toStdString());
    append_log("[MQTT-SENT] " + payload);
  } else {
    amqp_client->publish(entry_amqp_exchange->text().toStdString(),
                         entry_amqp_routing->text().toStdString(),
                         payload.toStdString());
    append_log("[AMQP-SENT] " + payload);
  }
}

void App::on_receiver_toggled(bool checked) {
  if (connected && combo_protocol->currentText() == "AMQP") {
    if (checked)
      amqp_client->start_consume();
    else
      amqp_client->stop_consume();
  }
}

void App::load_profile_list() {
  combo_profiles->clear();
  auto profiles = profile_manager.get_profiles();
  for (const auto &[name, p] : profiles) {
    combo_profiles->addItem(QString::fromStdString(name));
  }
}

void App::on_save_profile() {
  bool ok;
  QString name = QInputDialog::getText(
      this, "Save Profile", "Profile Name:", QLineEdit::Normal, "", &ok);
  if (ok && !name.isEmpty()) {
    Profile p;
    p.name = name.toStdString();
    p.protocol = combo_protocol->currentText().toStdString();
    p.host = entry_host->text().toStdString();
    p.port = entry_port->text().toStdString();
    p.username = entry_user->text().toStdString();
    p.password = entry_pass->text().toStdString();
    p.mqtt_topic = entry_mqtt_topic->text().toStdString();
    p.amqp_vhost = entry_amqp_vhost->text().toStdString();
    p.amqp_queue = entry_amqp_queue->text().toStdString();
    p.amqp_exchange = entry_amqp_exchange->text().toStdString();
    p.amqp_routing = entry_amqp_routing->text().toStdString();

    profile_manager.save(name.toStdString(), p);
    load_profile_list();
    combo_profiles->setCurrentText(name);
  }
}

void App::on_load_profile() {
  QString name = combo_profiles->currentText();
  if (name.isEmpty())
    return;

  auto profiles = profile_manager.get_profiles();
  std::string sname = name.toStdString();
  if (profiles.count(sname)) {
    const Profile &p = profiles.at(sname);
    combo_protocol->setCurrentText(QString::fromStdString(p.protocol));
    entry_host->setText(QString::fromStdString(p.host));
    entry_port->setText(QString::fromStdString(p.port));
    entry_user->setText(QString::fromStdString(p.username));
    entry_pass->setText(QString::fromStdString(p.password));
    entry_mqtt_topic->setText(QString::fromStdString(p.mqtt_topic));
    entry_amqp_vhost->setText(QString::fromStdString(p.amqp_vhost));
    entry_amqp_queue->setText(QString::fromStdString(p.amqp_queue));
    entry_amqp_exchange->setText(QString::fromStdString(p.amqp_exchange));
    entry_amqp_routing->setText(QString::fromStdString(p.amqp_routing));
    on_protocol_changed(combo_protocol->currentText());
  }
}

void App::on_delete_profile() {
  QString name = combo_profiles->currentText();
  if (name.isEmpty())
    return;

  if (QMessageBox::question(this, "Delete", "Delete profile " + name + "?") ==
      QMessageBox::Yes) {
    profile_manager.remove(name.toStdString());
    load_profile_list();
  }
}
