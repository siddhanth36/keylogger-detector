# 🔍 Keylogger Detector 
*A Python-based security tool to detect potential keyloggers in real-time*

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)

## 🚀 Features
- Scans running processes for known keylogger signatures
- Monitors suspicious directories for new executable files
- Detects unauthorized keyboard event listeners
- Real-time desktop alerts (using libnotify)
- Lightweight and configurable

#Detection Methods
-Process Analysis
-Checks process names/cmdlines against known keylogger patterns
-Filesystem Monitoring
-Watches temporary/autostart directories via inotify
-Device Inspection
-Verifies keyboard input devices using lsinput

## ⚙️ Installation
```bash
# Clone the repository
git clone https://github.com/siddhanth36/keylogger-detector.git
cd keylogger-detector

# Install dependencies
sudo apt install python3-psutil gir1.2-notify-0.7 input-utils
pip install -r requirements.txt

# Usage
# Run with standard privileges (basic detection)
python3 keylogger_detector.py

# Run as root (full monitoring)
sudo python3 keylogger_detector.py
