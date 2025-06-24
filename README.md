# macOS LaunchDaemon Setup

This guide explains how to install, load, and unload the LaunchDaemon plist that runs your Python script at system boot.

---

## 📌 Prerequisites
- macOS
- Administrator (sudo) access
- Your Python script (e.g., `/Users/x86/Public/secboot.py`)
- Your plist file (e.g., `com.example.secboot.plist`)

---

## 🚀 Installing the plist

1️⃣ Copy your plist to `/Library/LaunchDaemons/`:
```bash
sudo cp com.example.secboot.plist /Library/LaunchDaemons/
