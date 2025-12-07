import sys
import threading
import os
import json
import paho.mqtt.client as mqtt
import pika

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QFormLayout, QComboBox, QLineEdit, 
                             QPushButton, QLabel, QCheckBox, QTextEdit, 
                             QGroupBox, QStackedWidget, QMessageBox, QInputDialog)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import pyqtSignal, QObject, Qt, pyqtSlot

class ProtocolType:
    MQTT = "MQTT"
    AMQP = "AMQP"

class Signaller(QObject):
    log_message = pyqtSignal(str)

class MqttClientWrapper:
    def __init__(self, callback):
        self.client = None
        self.callback = callback
        self.connected = False
        self.topic = None

    def connect(self, host, port, username=None, password=None, topic=None):
        self.client = mqtt.Client()
        if username:
            self.client.username_pw_set(username, password)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.topic = topic
        self.client.connect(host, int(port), 60)
        self.client.loop_start()

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        self.connected = (rc == 0)
        if self.connected and self.topic:
            self.client.subscribe(self.topic)

    def _on_message(self, client, userdata, msg):
        try:
            payload = msg.payload.decode("utf-8", errors="ignore")
            self.callback(f"[MQTT] {msg.topic}: {payload}")
        except Exception:
            pass

    def publish(self, topic, payload):
        if self.client and self.connected:
            self.client.publish(topic, payload)

    def disconnect(self):
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
            self.connected = False

class AmqpClientWrapper:
    def __init__(self, callback):
        self.connection = None
        self.channel = None
        self.callback = callback
        self.consume_thread = None
        self._stop_event = threading.Event()
        self.queue_name = None

    def connect(self, host, port, vhost, username, password, queue_name):
        credentials = pika.PlainCredentials(username, password) if username else None
        params = pika.ConnectionParameters(
            host=host,
            port=int(port),
            virtual_host=vhost or "/",
            credentials=credentials,
        )
        self.connection = pika.BlockingConnection(params)
        self.channel = self.connection.channel()
        self.queue_name = queue_name
        self.channel.queue_declare(queue=queue_name, durable=False)

    def start_consume(self):
        if not self.channel:
            return

        self._stop_event.clear()
        def _consume():
            try:
                for method_frame, properties, body in self.channel.consume(self.queue_name, inactivity_timeout=1):
                    if self._stop_event.is_set():
                        break
                    if body is None:
                        continue
                    payload = body.decode("utf-8", errors="ignore")
                    self.callback(f"[AMQP] {self.queue_name}: {payload}")
                    self.channel.basic_ack(method_frame.delivery_tag)
            except Exception as e:
                # Provide some feedback if consumption fails
                # In a real app, perhaps signal back to UI
                pass

        self.consume_thread = threading.Thread(target=_consume, daemon=True)
        self.consume_thread.start()

    def stop_consume(self):
        self._stop_event.set()


    def publish(self, exchange, routing_key, payload):
        if self.channel:
            self.channel.basic_publish(
                exchange=exchange,
                routing_key=routing_key,
                body=payload.encode("utf-8"),
            )

    def disconnect(self):
        self.stop_consume()
        if self.channel and self.channel.is_open:
            self.channel.close()
        if self.connection and self.connection.is_open:
            self.connection.close()

# CSV Profile Manager adaptation
# JSON + Base64 Profile Manager
import base64

class ProfileManager:
    def __init__(self, filepath="profiles.txt"):
        self.filepath = filepath
        self.profiles = self.load_all()

    def load_all(self):
        data = {}
        if not os.path.exists(self.filepath):
            return data
        
        try:
            with open(self.filepath, "r") as f:
                content = f.read().strip()
                if not content: return data
                # Fix padding if necessary
                missing_padding = len(content) % 4
                if missing_padding:
                    content += '=' * (4 - missing_padding)
                json_str = base64.b64decode(content).decode("utf-8")
                data = json.loads(json_str)
        except Exception as e:
            print(f"Error loading profiles: {e}")
            # If data is corrupt, return empty dict so app can start
            data = {}
        return data

    def save_all(self):
        try:
            json_str = json.dumps(self.profiles)
            encoded = base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
            with open(self.filepath, "w") as f:
                f.write(encoded)
        except Exception as e:
            print(f"Error saving profiles: {e}")

    def save(self, name, data):
        data["name"] = name
        self.profiles[name] = data
        self.save_all()

    def delete(self, name):
        if name in self.profiles:
            del self.profiles[name]
            self.save_all()

class MessageBoxApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MessageBox : An MQTT & AMQP Tester")
        self.setWindowIcon(QIcon(os.path.join(os.path.dirname(__file__), "message.png")))
        self.resize(800, 600)

        self.signaller = Signaller()
        self.signaller.log_message.connect(self.append_log)

        self.profile_manager = ProfileManager()
        self.mqtt_client = MqttClientWrapper(self.signaller.log_message.emit)
        self.amqp_client = AmqpClientWrapper(self.signaller.log_message.emit)
        self.connected = False

        self._init_ui()

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # === Profiles ===
        profile_group = QGroupBox("Profiles")
        profile_layout = QHBoxLayout()
        self.combo_profiles = QComboBox()
        self.combo_profiles.setMinimumWidth(200)
        btn_load = QPushButton("Load")
        btn_load.clicked.connect(self.on_load_profile)
        btn_save = QPushButton("Save")
        btn_save.clicked.connect(self.on_save_profile)
        btn_delete = QPushButton("Delete")
        btn_delete.clicked.connect(self.on_delete_profile)
        
        profile_layout.addWidget(self.combo_profiles)
        profile_layout.addWidget(btn_load)
        profile_layout.addWidget(btn_save)
        profile_layout.addWidget(btn_delete)
        profile_layout.addStretch()
        profile_group.setLayout(profile_layout)
        main_layout.addWidget(profile_group)

        self.refresh_profile_list()

        # === Connection Settings ===
        conn_group = QGroupBox("Connection Settings")
        conn_layout = QFormLayout()

        self.combo_protocol = QComboBox()
        self.combo_protocol.addItems([ProtocolType.MQTT, ProtocolType.AMQP])
        self.combo_protocol.currentTextChanged.connect(self._on_protocol_change)
        conn_layout.addRow("Protocol:", self.combo_protocol)

        hbox_host = QHBoxLayout()
        self.entry_host = QLineEdit("localhost")
        self.entry_port = QLineEdit("1883")
        self.entry_port.setFixedWidth(80)
        hbox_host.addWidget(self.entry_host)
        hbox_host.addWidget(QLabel("Port:"))
        hbox_host.addWidget(self.entry_port)
        conn_layout.addRow("Host:", hbox_host)

        hbox_auth = QHBoxLayout()
        self.entry_user = QLineEdit()
        self.entry_pass = QLineEdit()
        self.entry_pass.setEchoMode(QLineEdit.EchoMode.Password)
        hbox_auth.addWidget(self.entry_user)
        hbox_auth.addWidget(QLabel("Password:"))
        hbox_auth.addWidget(self.entry_pass)
        conn_layout.addRow("Username:", hbox_auth)

        # Stacked widgets for protocol specifics
        self.stack_proto = QStackedWidget()
        
        # MQTT Page
        self.page_mqtt = QWidget()
        form_mqtt = QFormLayout()
        self.entry_topic = QLineEdit("test/topic")
        form_mqtt.addRow("MQTT Topic:", self.entry_topic)
        self.page_mqtt.setLayout(form_mqtt)
        self.stack_proto.addWidget(self.page_mqtt)

        # AMQP Page
        self.page_amqp = QWidget()
        form_amqp = QFormLayout()
        self.entry_vhost = QLineEdit("/")
        self.entry_queue = QLineEdit("test_queue")
        self.entry_exchange = QLineEdit("")
        self.entry_routing = QLineEdit("test_queue")
        
        hbox_amqp_1 = QHBoxLayout()
        hbox_amqp_1.addWidget(self.entry_vhost)
        hbox_amqp_1.addWidget(QLabel("Queue:"))
        hbox_amqp_1.addWidget(self.entry_queue)
        
        hbox_amqp_2 = QHBoxLayout()
        hbox_amqp_2.addWidget(self.entry_exchange)
        hbox_amqp_2.addWidget(QLabel("Routing Key:"))
        hbox_amqp_2.addWidget(self.entry_routing)

        form_amqp.addRow("VHost:", hbox_amqp_1)
        form_amqp.addRow("Exchange:", hbox_amqp_2)
        self.page_amqp.setLayout(form_amqp)
        self.stack_proto.addWidget(self.page_amqp)

        conn_layout.addRow(self.stack_proto)

        hbox_connect = QHBoxLayout()
        hbox_connect.addStretch()
        self.btn_connect = QPushButton("Connect")
        self.btn_connect.clicked.connect(self.on_connect_clicked)
        hbox_connect.addWidget(self.btn_connect)
        conn_layout.addRow(hbox_connect)

        conn_group.setLayout(conn_layout)
        main_layout.addWidget(conn_group)

        # === Bottom Section (Sender & Receiver) ===
        bottom_layout = QHBoxLayout()
        
        # === Sender ===
        sender_group = QGroupBox("Sender")
        sender_layout = QVBoxLayout()
        self.chk_sender = QCheckBox("Enable Sender")
        self.chk_sender.setChecked(True)
        self.chk_sender.toggled.connect(self._update_ui_state)
        sender_layout.addWidget(self.chk_sender)

        hbox_send = QHBoxLayout()
        hbox_send.addWidget(QLabel("Payload:"))
        self.entry_payload = QLineEdit()
        self.btn_send = QPushButton("Send")
        self.btn_send.clicked.connect(self.on_send_clicked)
        hbox_send.addWidget(self.entry_payload)
        hbox_send.addWidget(self.btn_send)
        sender_layout.addLayout(hbox_send)
        
        self.txt_sent_log = QTextEdit()
        self.txt_sent_log.setReadOnly(True)
        sender_layout.addWidget(self.txt_sent_log)
        
        # sender_layout.addStretch() # Push content up
        sender_group.setLayout(sender_layout)
        
        # === Receiver ===
        receiver_group = QGroupBox("Receiver")
        receiver_layout = QVBoxLayout()
        self.chk_receiver = QCheckBox("Enable Receiver")
        self.chk_receiver.setChecked(True)
        self.chk_receiver.toggled.connect(self.on_receiver_toggled)
        receiver_layout.addWidget(self.chk_receiver)

        self.txt_received_log = QTextEdit()
        self.txt_received_log.setReadOnly(True)
        receiver_layout.addWidget(self.txt_received_log)
        receiver_group.setLayout(receiver_layout)

        bottom_layout.addWidget(sender_group, 1) # Stretch factor 1
        bottom_layout.addWidget(receiver_group, 1) # Stretch factor 1
        main_layout.addLayout(bottom_layout)

        self._update_ui_state()

    def _on_protocol_change(self, text):
        if text == ProtocolType.MQTT:
            self.stack_proto.setCurrentWidget(self.page_mqtt)
            if self.entry_port.text() in ["5672", ""]:
                self.entry_port.setText("1883")
        else:
            self.stack_proto.setCurrentWidget(self.page_amqp)
            if self.entry_port.text() in ["1883", ""]:
                self.entry_port.setText("5672")

    def _update_ui_state(self):
        sender_enabled = self.connected and self.chk_sender.isChecked()
        self.entry_payload.setEnabled(sender_enabled)
        self.btn_send.setEnabled(sender_enabled)
        
        self.chk_sender.setEnabled(self.connected)
        self.chk_receiver.setEnabled(self.connected)

    def on_receiver_toggled(self):
        if self.connected and self.combo_protocol.currentText() == ProtocolType.AMQP:
            if self.chk_receiver.isChecked():
                self.amqp_client.start_consume()
            else:
                self.amqp_client.stop_consume()

    @pyqtSlot(str)
    def append_log(self, text):
        if text.startswith("[SEND]") or "Published" in text:
            self.txt_sent_log.append(text)
        else:
            self.txt_received_log.append(text)

    def on_connect_clicked(self):
        if self.connected:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        host = self.entry_host.text()
        port = self.entry_port.text()
        user = self.entry_user.text()
        pw = self.entry_pass.text()
        proto = self.combo_protocol.currentText()

        try:
            if proto == ProtocolType.MQTT:
                topic = self.entry_topic.text()
                self.mqtt_client.connect(host, port, user, pw, topic)
            else:
                vhost = self.entry_vhost.text()
                queue = self.entry_queue.text()
                self.amqp_client.connect(host, port, vhost, user, pw, queue)
            
            self.connected = True
            self.btn_connect.setText("Disconnect")
            self._update_ui_state()
            self.append_log(f"Connected to {proto}")

            if self.chk_receiver.isChecked() and proto == ProtocolType.AMQP:
                self.amqp_client.start_consume()

        except Exception as e:
            QMessageBox.critical(self, "Connection Error", str(e))
            self.connected = False

    def disconnect(self):
        proto = self.combo_protocol.currentText()
        if proto == ProtocolType.MQTT:
            self.mqtt_client.disconnect()
        else:
            self.amqp_client.disconnect()
        
        self.connected = False
        self.btn_connect.setText("Connect")
        self._update_ui_state()
        self.append_log("Disconnected.")

    def on_send_clicked(self):
        payload = self.entry_payload.text()
        if not payload: return
        
        proto = self.combo_protocol.currentText()
        if proto == ProtocolType.MQTT:
            self.mqtt_client.publish(self.entry_topic.text(), payload)
            self.append_log(f"[MQTT-SENT] {payload}")
        else:
            self.amqp_client.publish(self.entry_exchange.text(), self.entry_routing.text(), payload)
            self.append_log(f"[AMQP-SENT] {payload}")

    def refresh_profile_list(self):
        self.combo_profiles.clear()
        self.combo_profiles.addItems(list(self.profile_manager.profiles.keys()))

    def on_save_profile(self):
        name, ok = QInputDialog.getText(self, "Save Profile", "Enter profile name:")
        if ok and name:
            data = {
                "protocol": self.combo_protocol.currentText(),
                "host": self.entry_host.text(),
                "port": self.entry_port.text(),
                "username": self.entry_user.text(),
                "password": self.entry_pass.text(),
                "mqtt_topic": self.entry_topic.text(),
                "amqp_vhost": self.entry_vhost.text(),
                "amqp_queue": self.entry_queue.text(),
                "amqp_exchange": self.entry_exchange.text(),
                "amqp_routing": self.entry_routing.text()
            }
            self.profile_manager.save(name, data)
            self.refresh_profile_list()
            self.combo_profiles.setCurrentText(name)

    def on_load_profile(self):
        name = self.combo_profiles.currentText()
        if not name: return
        data = self.profile_manager.profiles.get(name)
        if data:
            self.combo_protocol.setCurrentText(data.get("protocol", "MQTT"))
            self.entry_host.setText(data.get("host", ""))
            self.entry_port.setText(data.get("port", ""))
            self.entry_user.setText(data.get("username", ""))
            self.entry_pass.setText(data.get("password", ""))
            self.entry_topic.setText(data.get("mqtt_topic", ""))
            self.entry_vhost.setText(data.get("amqp_vhost", ""))
            self.entry_queue.setText(data.get("amqp_queue", ""))
            self.entry_exchange.setText(data.get("amqp_exchange", ""))
            self.entry_routing.setText(data.get("amqp_routing", ""))
            self._on_protocol_change(self.combo_protocol.currentText())

    def on_delete_profile(self):
        name = self.combo_profiles.currentText()
        if name:
             self.profile_manager.delete(name)
             self.refresh_profile_list()

def main():
    app = QApplication(sys.argv)
    window = MessageBoxApp()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
