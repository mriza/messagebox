import threading
import queue
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import scrolledtext, messagebox

import paho.mqtt.client as mqtt
import pika

class ProtocolType:
    MQTT = "MQTT"
    AMQP = "AMQP"

class MqttClientWrapper:
    def __init__(self, on_message_callback):
        self.client = None
        self.on_message_callback = on_message_callback
        self.connected = False

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
        payload = msg.payload.decode("utf-8", errors="ignore")
        self.on_message_callback(f"[MQTT] {msg.topic}: {payload}")

    def publish(self, topic, payload):
        if self.client and self.connected:
            self.client.publish(topic, payload)
    def disconnect(self):
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
            self.connected = False

class AmqpClientWrapper:
    def __init__(self, on_message_callback):
        self.connection = None
        self.channel = None
        self.on_message_callback = on_message_callback
        self.consume_thread = None
        self._stop_event = threading.Event()
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
            for method_frame, properties, body in self.channel.consume(self.queue_name, inactivity_timeout=1):
                if self._stop_event.is_set():
                    break
                if body is None:
                    continue
                payload = body.decode("utf-8", errors="ignore")
                self.on_message_callback(f"[AMQP] {self.queue_name}: {payload}")
                self.channel.basic_ack(method_frame.delivery_tag)

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

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("MQTT & AMQP Tester")
        self.msg_queue = queue.Queue()
        self.current_protocol = tk.StringVar(value=ProtocolType.MQTT)
        self.mqtt_client = MqttClientWrapper(self.enqueue_message)
        self.amqp_client = AmqpClientWrapper(self.enqueue_message)
        self.connected = False
        self._build_gui()
        self._set_sender_receiver_state("disabled")
        self.root.after(100, self._process_queue)

    def _build_gui(self):
        top_frame = ttk.Labelframe(self.root, text="Connection Settings", padding=10)
        top_frame.pack(fill="x", padx=10, pady=10)

        proto_label = ttk.Label(top_frame, text="Protocol:")
        proto_label.grid(row=0, column=0, sticky="w")
        proto_combo = ttk.Combobox(
            top_frame,
            values=[ProtocolType.MQTT, ProtocolType.AMQP],
            textvariable=self.current_protocol,
            state="readonly",
            width=8,
        )
        proto_combo.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(top_frame, text="Host:").grid(row=1, column=0, sticky="w")
        self.entry_host = ttk.Entry(top_frame, width=25)
        self.entry_host.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        self.entry_host.insert(0, "localhost")

        ttk.Label(top_frame, text="Port:").grid(row=1, column=2, sticky="w")
        self.entry_port = ttk.Entry(top_frame, width=6)
        self.entry_port.grid(row=1, column=3, sticky="w", padx=5, pady=2)
        self.entry_port.insert(0, "1883")  # default MQTT

        ttk.Label(top_frame, text="Username:").grid(row=2, column=0, sticky="w")
        self.entry_user = ttk.Entry(top_frame, width=25)
        self.entry_user.grid(row=2, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(top_frame, text="Password:").grid(row=2, column=2, sticky="w")
        self.entry_pass = ttk.Entry(top_frame, width=15, show="*")
        self.entry_pass.grid(row=2, column=3, sticky="w", padx=5, pady=2)

        # Subframe hanya untuk MQTT
        self.mqtt_frame = ttk.Frame(top_frame)
        self.mqtt_frame.grid(row=3, column=0, columnspan=4, sticky="we", padx=2, pady=2)
        ttk.Label(self.mqtt_frame, text="MQTT Topic:").grid(row=0, column=0, sticky="w")
        self.entry_topic = ttk.Entry(self.mqtt_frame, width=30)
        self.entry_topic.grid(row=0, column=1, sticky="w")
        self.entry_topic.insert(0, "test/topic")

        # Subframe hanya untuk AMQP
        self.amqp_frame = ttk.Frame(top_frame)
        self.amqp_frame.grid(row=3, column=0, columnspan=4, sticky="we", padx=2, pady=2)
        ttk.Label(self.amqp_frame, text="AMQP vhost:").grid(row=0, column=0, sticky="w")
        self.entry_vhost = ttk.Entry(self.amqp_frame, width=10)
        self.entry_vhost.grid(row=0, column=1, sticky="w")
        self.entry_vhost.insert(0, "/")
        ttk.Label(self.amqp_frame, text="Queue:").grid(row=0, column=2, sticky="w", padx=(10,0))
        self.entry_queue = ttk.Entry(self.amqp_frame, width=13)
        self.entry_queue.grid(row=0, column=3, sticky="w")
        self.entry_queue.insert(0, "test_queue")
        ttk.Label(self.amqp_frame, text="Exchange:").grid(row=1, column=0, sticky="w")
        self.entry_exchange = ttk.Entry(self.amqp_frame, width=15)
        self.entry_exchange.grid(row=1, column=1, sticky="w")
        self.entry_exchange.insert(0, "")
        ttk.Label(self.amqp_frame, text="Routing Key:").grid(row=1, column=2, sticky="w", padx=(10,0))
        self.entry_routing = ttk.Entry(self.amqp_frame, width=13)
        self.entry_routing.grid(row=1, column=3, sticky="w")
        self.entry_routing.insert(0, "test_queue")

        self.btn_connect = ttk.Button(top_frame, text="Connect", bootstyle=SUCCESS, command=self.on_connect_clicked)
        self.btn_connect.grid(row=0, column=3, sticky="e", padx=5)

        self.current_protocol.trace_add("write", self._on_protocol_change)
        self._on_protocol_change()

        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        sender_frame = ttk.Labelframe(bottom_frame, text="Sender", padding=10)
        sender_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        self.var_enable_sender = tk.BooleanVar(value=True)
        chk_sender = ttk.Checkbutton(sender_frame, text="Enable Sender", variable=self.var_enable_sender,
                                     command=self._update_sender_state)
        chk_sender.pack(anchor="w")

        ttk.Label(sender_frame, text="Payload:").pack(anchor="w")
        self.entry_payload = ttk.Entry(sender_frame)
        self.entry_payload.pack(fill="x", pady=5)

        self.btn_send = ttk.Button(sender_frame, text="Send", command=self.on_send_clicked, bootstyle=PRIMARY)
        self.btn_send.pack(anchor="e", pady=5)

        receiver_frame = ttk.Labelframe(bottom_frame, text="Receiver", padding=10)
        receiver_frame.pack(side="left", fill="both", expand=True, padx=(5, 0))

        self.var_enable_receiver = tk.BooleanVar(value=True)
        chk_receiver = ttk.Checkbutton(receiver_frame, text="Enable Receiver", variable=self.var_enable_receiver,
                                       command=self._update_receiver_state)
        chk_receiver.pack(anchor="w")

        ttk.Label(receiver_frame, text="Messages:").pack(anchor="w")
        self.text_messages = scrolledtext.ScrolledText(receiver_frame, wrap="word", height=15)
        self.text_messages.pack(fill="both", expand=True, pady=5)

    def _on_protocol_change(self, *args):
        proto = self.current_protocol.get()
        if proto == ProtocolType.MQTT:
            self.entry_port.delete(0, tk.END)
            self.entry_port.insert(0, "1883")
            self.mqtt_frame.grid()           # Tampilkan hanya frame MQTT
            self.amqp_frame.grid_remove()    # Sembunyikan frame AMQP
        else:
            self.entry_port.delete(0, tk.END)
            self.entry_port.insert(0, "5672")
            self.amqp_frame.grid()           # Tampilkan hanya frame AMQP
            self.mqtt_frame.grid_remove()    # Sembunyikan frame MQTT

    def _set_sender_receiver_state(self, state):
        self.entry_payload.configure(state=state)
        self.btn_send.configure(state=state)
        self.text_messages.configure(state=state)

    def _update_sender_state(self):
        if not self.connected:
            self._set_sender_receiver_state("disabled")
            return
        if self.var_enable_sender.get():
            self.entry_payload.configure(state="normal")
            self.btn_send.configure(state="normal")
        else:
            self.entry_payload.configure(state="disabled")
            self.btn_send.configure(state="disabled")

    def _update_receiver_state(self):
        if not self.connected:
            self._set_sender_receiver_state("disabled")
            return
        if self.var_enable_receiver.get():
            self.text_messages.configure(state="normal")
            if self.current_protocol.get() == ProtocolType.AMQP:
                self.amqp_client.start_consume()
        else:
            if self.current_protocol.get() == ProtocolType.AMQP:
                self.amqp_client.stop_consume()

    def on_connect_clicked(self):
        if not self.connected:
            self._do_connect()
        else:
            self._do_disconnect()

    def _do_connect(self):
        host = self.entry_host.get().strip()
        port = self.entry_port.get().strip()
        username = self.entry_user.get().strip() or None
        password = self.entry_pass.get().strip() or None
        proto = self.current_protocol.get()
        try:
            if proto == ProtocolType.MQTT:
                topic = self.entry_topic.get().strip()
                self.mqtt_client.connect(host, port, username, password, topic)
            else:
                vhost = self.entry_vhost.get().strip()
                queue_name = self.entry_queue.get().strip()
                self.amqp_client.connect(host, port, vhost, username, password, queue_name)
            self.connected = True
        except Exception as e:
            messagebox.showerror("Connection error", str(e))
            self.connected = False
            return

        if self.connected:
            self.btn_connect.configure(text="Disconnect", bootstyle=DANGER)
            self._set_sender_receiver_state("normal")
            self._update_sender_state()
            self._update_receiver_state()
            self.enqueue_message(f"Connected using {proto}")

    def _do_disconnect(self):
        proto = self.current_protocol.get()
        if proto == ProtocolType.MQTT:
            self.mqtt_client.disconnect()
        else:
            self.amqp_client.disconnect()
        self.connected = False
        self.btn_connect.configure(text="Connect", bootstyle=SUCCESS)
        self._set_sender_receiver_state("disabled")
        self.enqueue_message(f"Disconnected from {proto}")

    def on_send_clicked(self):
        if not self.connected:
            messagebox.showwarning("Not connected", "Please connect first.")
            return
        if not self.var_enable_sender.get():
            return
        payload = self.entry_payload.get()
        if not payload:
            messagebox.showwarning("Empty payload", "Please enter payload.")
            return
        proto = self.current_protocol.get()
        try:
            if proto == ProtocolType.MQTT:
                topic = self.entry_topic.get().strip()
                self.mqtt_client.publish(topic, payload)
                self.enqueue_message(f"[MQTT-SENT] {topic}: {payload}")
            else:
                exchange = self.entry_exchange.get().strip()
                routing_key = self.entry_routing.get().strip() or self.entry_queue.get().strip()
                self.amqp_client.publish(exchange, routing_key, payload)
                self.enqueue_message(f"[AMQP-SENT] {routing_key}: {payload}")
        except Exception as e:
            messagebox.showerror("Send error", str(e))

    def enqueue_message(self, text):
        self.msg_queue.put(text)

    def _process_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                self.text_messages.configure(state="normal")
                self.text_messages.insert(tk.END, msg + "\n")
                self.text_messages.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self._process_queue)

def main():
    app = ttk.Window(themename="flatly")
    App(app)
    app.geometry("900x500")
    app.mainloop()

if __name__ == "__main__":
    main()
