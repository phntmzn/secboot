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

✅ **Here’s exactly how to set permissions for your LaunchDaemon plist on macOS:**

---

### 📂 Assuming your plist is:
```
/Library/LaunchDaemons/com.example.secboot.plist
```

### 🛠 **Run these commands in Terminal:**
```bash
# Set ownership to root:wheel
sudo chown root:wheel /Library/LaunchDaemons/com.example.secboot.plist

# Set permissions to 644 (rw-r--r--)
sudo chmod 644 /Library/LaunchDaemons/com.example.secboot.plist
```

---

### ⚠ Why this is important:
- `root:wheel` ensures only the root user owns and controls the plist.
- `644` permissions:
  ```
  -rw-r--r--
  ```
  ➡ Root can read/write.  
  ➡ Everyone else can only read.

macOS `launchd` **requires** these permissions for security — it will refuse to load a plist that has incorrect permissions.

---

### ✅ Check permissions:
```bash
ls -l /Library/LaunchDaemons/com.example.secboot.plist
```
Expected output:
```
-rw-r--r--  1 root  wheel  [size] [date] com.example.secboot.plist
```

---

If you'd like, I can generate the full set of commands as a script or integrate it into your README! Let me know 🚀.
