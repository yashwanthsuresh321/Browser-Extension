# 🔍 Browser History Analyzer & Malicious URL Detector:

A **browser extension** integrated with a **Java backend server** that analyzes your browsing history, identifies suspicious or malicious URLs, and provides visual reports for safer web usage.

---

## 🧠 Overview

This project combines:
- A **browser extension** (JavaScript + manifest) to capture and send browsing data.
- A **Java-based backend server** that stores, analyzes, and classifies URLs.
- An embedded **SQLite database** for history tracking and frequency analysis.
- Optional **VirusTotal integration (VTScanResult)** for real-time malicious URL scanning.

---

## 🚀 Features

✅ **Real-time URL monitoring** — Detects URLs as you browse  
✅ **Malicious URL detection** — Identifies risky sites using rule-based or API-based checks  
✅ **History analysis** — Parses and stores browsing history in SQLite  
✅ **Visual report popup** — Displays alerts and analysis via the extension popup  
✅ **Database integration** — Maintains scan results and URL frequencies locally  
✅ **Modular architecture** — Easily extendable for new scanning methods  

---

## 🏗️ Project Structure

```
Browser-Extension-main/
├── manifest.json                 # Extension configuration
├── background.js                 # Listens for web requests and sends data to backend
├── popup.html                    # Extension popup UI
├── popup.js                      # Handles frontend logic for popup
├── blocked.html                  # Warning page for blocked URLs
├── icon48.svg                    # Extension icon
├── rules.json                    # URL filtering rules
│
├── CommunicationServer.java      # Handles client-server communication
├── DatabaseManager.java          # Manages SQLite database
├── HistoryParser.java            # Parses and stores browser history
├── URLAnalyzer.java              # Detects URL patterns and frequencies
├── VTScanResult.java             # VirusTotal integration (optional)
├── Main.java                     # Entry point for Java server
│
├── history_analyzer.db           # SQLite database
├── sqlite-jdbc.jar               # JDBC library for database connection
│
├── build.bat / compile.bat       # Windows batch scripts for building
├── create_jar.bat                # Packages Java files into a runnable JAR
├── HistoryAnalyzer.bat           # Quick-start script
└── Change/                       # (Optional) Change logs or configs
```

---

## ⚙️ How It Works

1. **Browser extension** captures browsing events.  
2. Sends URLs to the **Java server** via a local communication port.  
3. The **backend**:
   - Parses URLs and stores them in the SQLite database.  
   - Runs analysis using `URLAnalyzer` and optionally VirusTotal API.  
   - Returns a verdict (safe / suspicious / malicious).  
4. The **popup UI** displays the result instantly.  

---

## 🧩 Installation & Setup

### 🧰 Requirements
- **Java 11+**
- **SQLite JDBC**
- **Browser with extension developer mode (Chrome, Edge, or Brave)**

---

### ⚙️ Setup Steps

#### 1️⃣ Run the Java Backend
```bash
# On Windows
compile.bat
create_jar.bat
HistoryAnalyzer.bat
```
This starts the local server (`CommunicationServer`) that listens for URL analysis requests.

#### 2️⃣ Load the Browser Extension
1. Open your browser → Extensions → **Developer Mode: ON**  
2. Click **Load unpacked** → Select the `Browser-Extension-main/` folder  
3. The extension icon should appear in the toolbar  

#### 3️⃣ Start Browsing
- The extension monitors visited URLs  
- The backend classifies them  
- Alerts and logs appear in your **popup UI**

---

## 🧮 Database Schema

| Table | Description |
|--------|--------------|
| `history` | Stores URL, timestamp, and status |
| `scan_results` | Holds VirusTotal or analyzer results |
| `url_frequency` | Tracks visit counts for frequent analysis |

---

## 🧠 Key Java Classes

| Class | Purpose |
|--------|----------|
| `CommunicationServer` | Manages HTTP communication between browser and backend |
| `DatabaseManager` | Creates and maintains SQLite database |
| `URLAnalyzer` | Checks URLs for patterns, phishing attempts, and frequency |
| `HistoryParser` | Extracts and stores browsing data |
| `VTScanResult` | Integrates with VirusTotal API (if configured) |

---

## 💡 Example Workflow

1. You visit `example.com`  
2. The extension sends `example.com` → `CommunicationServer`  
3. Server analyzes via `URLAnalyzer`  
4. If flagged malicious → `blocked.html` is shown  
   Else → Safe browsing continues  

---

## 🧰 Build from Source

```bash
# Compile Java source files
javac -cp ".;sqlite-jdbc.jar" *.java

# Package into JAR
jar cfm HistoryAnalyzer.jar Manifest.txt *.class

# Run
java -jar HistoryAnalyzer.jar
```

---

## 🧪 Testing

Run built-in tests with:
```bash
python -m warp.tests
```
Or manually visit sample URLs defined in `rules.json`.

---

## 🛠️ Technologies Used

- **Java 11+** — Core backend logic  
- **SQLite** — Embedded database  
- **HTML / JS / CSS** — Extension frontend  
- **JSON** — Communication and rules  
- **VirusTotal API (optional)** — External malicious scan verification  

---

## 🧑‍💻 Author

P Harshamithran,
Navneet Nanda,
Yashwant S
🧠 Developed as part of a cybersecurity and browser-safety research project.

---

## 🪪 License

This project is licensed under the **MIT License**.  
You are free to modify and redistribute it with attribution.

---

## ⭐ Future Enhancements

- Add real-time phishing site detection  
- Integrate with browser sandbox for isolation  
- Expand to Firefox/Edge extension stores  
- Add analytics dashboard for visualization  
