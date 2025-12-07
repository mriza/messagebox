# MessageBox (MQTT & AMQP Tester)

A cross-platform GUI application for testing MQTT and AMQP messaging, built with **Qt6**. Available in both **C++** (Qt6) and **Python** (PyQt6) versions.

## Features
-   **Protocols**: MQTT (using `libmosquitto`/`paho-mqtt`) and AMQP (using `librabbitmq-c`/`pika`).
-   **Profiles**: Save and load connection profiles (encrypted storage).
-   **GUI**: Native look and feel using Qt6.
-   **Layout**: Side-by-side Sender/Receiver view with **separate logs** for Sent and Received messages.

## 📥 Download
Pre-built binaries for Linux are available on the [GitHub Releases](https://github.com/USER/messagebox/releases) page.

---

## 🛠️ C++ Version (Qt6)

### Prerequisites (Linux)
**Fedora**:
```bash
sudo dnf install qt6-qtbase-devel libmosquitto-devel librabbitmq-devel nlohmann-json-devel cmake gcc-c++ git
```

**Debian/Ubuntu**:
```bash
sudo apt install qt6-base-dev libmosquitto-dev librabbitmq-dev nlohmann-json3-dev build-essential cmake git
```

### Build & Run (Linux)
```bash
# 1. Clone the repository
git clone https://github.com/USER/messagebox.git
cd messagebox

# 2. Build
mkdir build && cd build
cmake ..
make

# 3. Run
./messagebox
```

### Build & Run (Windows via MSYS2)
1.  Install **MSYS2**.
2.  Open **MSYS2 MinGW 64-bit** terminal.
3.  Install dependencies:
    ```bash
    pacman -S mingw-w64-x86_64-qt6-base mingw-w64-x86_64-mosquitto mingw-w64-x86_64-rabbitmq-c mingw-w64-x86_64-nlohmann-json mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc git
    ```
4.  Build and run:
    ```bash
    mkdir build && cd build
    cmake .. -G "MinGW Makefiles"
    cmake --build .
    ./messagebox.exe
    ```

### Cross-Compilation (Linux -> Windows)
*Note: Direct cross-compilation from Linux requires `mingw64-qt6` packages which may not be available in standard repositories. Using MSYS2 on Windows (above) is recommended.*

If you have a custom environment with MinGW Qt6, you can use the provided toolchain:
```bash
mkdir build-win
cd build-win
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchain-mingw.cmake ..
make
```

### Run
```bash
./messagebox
```

---

## Python Version

### Installation

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

### Usage

Run the GUI:
```bash
python messagebox.py
```