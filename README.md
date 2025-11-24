# MQTT & AMQP Connection Tester (Python GUI)

A simple desktop GUI tool to test connections and messaging with MQTT brokers and AMQP (RabbitMQ) servers.  
The interface adapts to the selected protocol and allows sending and receiving messages interactively.

## Features
- Switch between MQTT and AMQP (RabbitMQ).
- Modern GUI built with ttkbootstrap.
- Independent Sender and Receiver panels (can be enabled/disabled).
- Real-time sent and received message logs.
- Only relevant connection fields shown per protocol.

## Installation

1. Clone the repository
```bash
git clone https://github.com/mriza/messagebox.git
cd messagebox
```

2. Create and activate a virtual environment
```bash
python -m venv venv
# On Linux/macOS
source venv/bin/activate
# On Windows (PowerShell)
venv\Scripts\Activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

## Usage

Run the GUI:
```bash
python messagebox.py
```

1. Select protocol (MQTT or AMQP).
2. Fill in connection settings (fields adapt to the selected protocol).
3. Click "Connect".
4. Use the Sender panel to publish messages.
5. View incoming messages in the Receiver panel.

## Requirements
- Python 3.8+
- Dependencies listed in requirements.txt
- MQTT broker (e.g., Mosquitto, EMQX) for MQTT testing
- RabbitMQ for AMQP testing