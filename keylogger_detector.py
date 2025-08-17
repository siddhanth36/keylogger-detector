#!/usr/bin/env python3
import psutil
import time
from gi.repository import Notify
import re
import pyinotify
import subprocess

# Known keylogger indicators
KEYLOGGER_SIGNATURES = [
    "keylog", "logkeys", "kidlogger", "spyware", 
    "keysniffer", "keyghost", "keytap", "lkl"
]

SUSPICIOUS_PATHS = [
    "/tmp/", "/dev/shm/", "/var/tmp/",  # Common temp directories
    "/.config/autostart/", "/.local/share/"  # Common persistence locations
]

class EventHandler(pyinotify.ProcessEvent):
    def my_init(self, **kwargs):
        self.notifier = kwargs.get('notifier')

    def process_IN_CREATE(self, event):
        if any(susp_path in event.pathname for susp_path in SUSPICIOUS_PATHS):
            alert(f"Suspicious file created: {event.pathname}")

def scan_processes():
    """Check running processes for keylogger indicators"""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
        try:
            # Check process name and cmdline
            proc_info = f"{proc.info['name']} {' '.join(proc.info['cmdline'])}".lower()
            
            # Check against signatures
            if any(sig in proc_info for sig in KEYLOGGER_SIGNATURES):
                alert(f"Keylogger process detected!\nPID: {proc.info['pid']}\nName: {proc.info['name']}")
                
            # Check suspicious binary locations
            if proc.info['exe'] and any(susp_path in proc.info['exe'] for susp_path in SUSPICIOUS_PATHS):
                alert(f"Process running from suspicious location:\n{proc.info['exe']}")
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def alert(message):
    """Show desktop notification"""
    Notify.init("Keylogger Detector")
    notification = Notify.Notification.new(
        "⚠️ Security Alert",
        message,
        "dialog-warning"
    )
    notification.show()
    print(f"[ALERT] {message}")

def monitor_keyboard_devices():
    """Check for unauthorized keyboard event listeners"""
    try:
        # List input devices
        result = subprocess.run(['lsinput'], capture_output=True, text=True)
        devices = result.stdout.split('\n')
        
        keyboard_devices = [d for d in devices if "keyboard" in d.lower()]
        print(f"Detected keyboard devices:\n{keyboard_devices}")
        
    except FileNotFoundError:
        print("lsinput not found. Install 'input-utils' package for detailed monitoring.")

def start_monitoring():
    """Main monitoring loop"""
    print("🔍 Starting keylogger detection...")
    print(f"Monitoring for: {KEYLOGGER_SIGNATURES}")
    
    # Initialize inotify for file monitoring
    wm = pyinotify.WatchManager()
    handler = EventHandler(notifier=wm)
    notifier = pyinotify.Notifier(wm, handler)
    
    # Watch suspicious directories
    for path in SUSPICIOUS_PATHS:
        try:
            wm.add_watch(path, pyinotify.IN_CREATE)
        except:
            continue
    
    # Main loop
    while True:
        scan_processes()
        monitor_keyboard_devices()
        
        # Process inotify events
        notifier.process_events()
        if notifier.check_events():
            notifier.read_events()
        
        time.sleep(10)  # Check every 10 seconds

if __name__ == "__main__":
    try:
        start_monitoring()
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped")
