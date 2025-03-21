# TCP-Licencing-System
# License Generator

## 🚀 Overview
This is a simple **License Generator** that allows users to generate signed licenses for domains or clients. It uses **RSA encryption** to sign the license and stores the data securely in an **SQLite database**. The application runs as a lightweight **HTTP server**, serving a simple HTML form for user input.

## 📌 Features
- **No external frameworks required** (uses built-in Python modules)
- **Generates signed licenses** using RSA encryption
- **Stores license details in SQLite** for persistence
- **Lightweight HTTP server** for handling form submissions
- **Simple web interface** for license generation

## 📦 Requirements
- Python 3.x
- SQLite (built-in with Python)
- No additional dependencies

## 🛠 Installation & Setup
### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/license-generator.git
cd license-generator
```

### 2️⃣ Run the Script
```bash
python licence.py
```

### 3️⃣ Open in Browser
Go to `http://localhost:8080` in your web browser to access the **License Generator** form.

## 🎯 How It Works
1. **User fills out the form** (Client ID, License Type, Duration).
2. **Python server processes the request**, signs the license, and stores it in SQLite.
3. **Generated license is displayed** on the page and stored in the database.

## 🔑 License Data Format
Each generated license contains:
```json
{
    "client_id": "example.com",
    "license_type": "Pro",
    "exp": 1729296000,
    "issued_at": 1710748800
}
```
- **client_id**: The domain or name of the client
- **license_type**: Type of license (Basic, Pro, Enterprise)
- **exp**: Expiry timestamp
- **issued_at**: Issued timestamp
- **signature**: RSA-signed string (stored in the database)

## 🏗 Database Schema (SQLite)
```sql
CREATE TABLE licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT UNIQUE NOT NULL,
    license_type TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    exp INTEGER NOT NULL,
    signature TEXT NOT NULL
);
```

## 🛑 Stopping the Server
Press `CTRL + C` in the terminal to stop the server.

## 📜 License
This project is open-source under the **MIT License**. Feel free to modify and use it!

---
💡 **Suggestions or Issues?** Open an issue or contribute! 🚀

