# 🛡️ BrowserShield

**Real-time browser security monitoring application + Chrome extension.**

BrowserShield reads actual browser data (history, bookmarks, extensions) from all installed browsers, monitors your network connections in real-time, detects ads/trackers, and uses AI agents (Gemini, OpenAI, Claude) for intelligent threat analysis.

![Dashboard](https://img.shields.io/badge/Dashboard-Live-00d4aa?style=for-the-badge)
![Extension](https://img.shields.io/badge/Chrome_Extension-v2.0-6366f1?style=for-the-badge)
![AI](https://img.shields.io/badge/AI_Agents-Gemini%20%7C%20OpenAI%20%7C%20Claude-f59e0b?style=for-the-badge)

---

## ✨ Features

### 🖥️ Dashboard
- **Real browser history** from Chrome, Safari, Edge, Brave, Firefox
- **Real bookmarks** from all browsers
- **52+ installed apps** detection with categories
- **11+ browser extensions** with risk analysis
- **Activity heatmap** (24-hour view)
- **Threat breakdown** with risk scoring

### 📡 Network Monitor
- **Upload/Download bandwidth** tracking (real-time)
- **Active connections** table with process names
- **Hidden packet detection** — catches suspicious connections
- **Data exfiltration monitoring** — flags connections to pastebin, ngrok, webhook.site, etc.
- **Suspicious port scanning** — detects ports 4444, 1337, 31337, etc.

### 🤖 AI Security Agents
- **Gemini, OpenAI, Claude** integration
- API keys stored in `.env` (never hardcoded)
- **Auto-analyze threats** — AI activates when threats are detected
- **Test any URL** with AI from the dashboard
- Alerts pushed to Live Activity stream

### 🔍 URL Detail Modal
- Click any URL in history to see **full details**
- Total visits, unique pages, first/last visit
- **30-day visit graph** (bar chart)
- **Browser breakdown** (which browser visited most)
- Recent pages list on that domain

### ⚡ Live Activity
- **Real-time URL monitoring** as you browse
- Browser open/close detection
- WebSocket-powered live updates

### 🚫 Ads & Trackers
- **Ad/tracker detection** across browsing history
- Top ad networks breakdown
- Percentage of browsing affected

### 🧩 Chrome Extension (v2.0)
- **4-tab popup**: Security, Time, Extensions, Settings
- **Time tracking** per domain
- **IP address resolution** (Cloudflare DNS-over-HTTPS)
- **Ad blocking** — 50 declarativeNetRequest rules + DOM ad removal
- **Settings** — on/off toggles, custom block/allow URL lists
- **Extension listing** via chrome.management API

---

## 📦 Installation

### Prerequisites
- **Node.js** v18+ ([Download](https://nodejs.org))
- **npm** (comes with Node.js)
- macOS, Windows, or Linux

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Jalendar10/Browsershield.git
cd Browsershield

# 2. Install dependencies
npm install

# 3. Start the server
npm start
```

The dashboard opens at **http://localhost:3847** 🚀

### Install the Chrome Extension

```bash
# Auto-open browser extension pages
npm run install-extension
```

Then in the browser:
1. Enable **Developer mode** (top-right toggle)
2. Click **Load unpacked**
3. Select the `extension/` folder from this project

### Enable Auto-Start on Login

```bash
npm run autostart
```

This creates a LaunchAgent (macOS) so BrowserShield starts automatically when you log in.

---

## 🤖 AI Setup (Optional)

To enable AI-powered threat analysis, add your API keys:

### Option 1: Via Dashboard
1. Go to **AI Settings** in the sidebar
2. Enter your API key(s)
3. Click **Save AI Settings**

### Option 2: Via .env file

Create a `.env` file in the project root:

```env
# Choose: gemini, openai, or claude
AI_PROVIDER=gemini

# Google Gemini (https://aistudio.google.com/apikey)
GEMINI_API_KEY=your_key_here

# OpenAI (https://platform.openai.com/api-keys)
OPENAI_API_KEY=your_key_here

# Anthropic Claude (https://console.anthropic.com/)
CLAUDE_API_KEY=your_key_here
```

---

## 🗂️ Project Structure

```
Browsershield/
├── server.js                    # Express + WebSocket server
├── package.json                 # Dependencies & scripts
├── .env                         # AI API keys (not committed)
├── public/                      # Frontend dashboard
│   ├── index.html               # Main dashboard (9 sections)
│   ├── styles.css               # Dark cybersecurity theme
│   └── app.js                   # Frontend logic
├── src/core/                    # Backend modules
│   ├── browser-detector.js      # Detect installed browsers
│   ├── history-reader.js        # Read browser history (SQLite)
│   ├── bookmark-reader.js       # Read bookmarks
│   ├── threat-analyzer.js       # URL threat scoring
│   ├── live-monitor.js          # File system watcher
│   ├── process-monitor.js       # Running browser detection
│   ├── app-monitor.js           # Installed apps scanner
│   ├── extension-reader.js      # Browser extensions reader
│   ├── ad-tracker.js            # Ad/tracker analysis
│   ├── network-monitor.js       # Bandwidth & connection monitor
│   └── ai-agents.js             # Gemini/OpenAI/Claude integration
├── extension/                   # Chrome Extension (Manifest V3)
│   ├── manifest.json            # Extension config
│   ├── background.js            # Service worker
│   ├── content.js               # Ad blocker & DOM scanner
│   ├── popup.html/css/js        # 4-tab popup UI
│   ├── rules.json               # 50 ad-blocking rules
│   └── icons/                   # Extension icons
└── scripts/                     # Utility scripts
    ├── install-extension.js     # Auto-open extension pages
    └── autostart.js             # Enable auto-start on login
```

---

## 🛠️ Scripts

| Command | Description |
|---------|-------------|
| `npm start` | Start BrowserShield server at http://localhost:3847 |
| `npm run install-extension` | Open browser extension pages for installation |
| `npm run autostart` | Enable auto-start on login |

---

## 📸 Screenshots

### Dashboard
Full overview with 8 stat cards, detected browsers, top domains, activity heatmap, and threat breakdown.

### Network Monitor
Real-time bandwidth (upload/download), active connections table, hidden packet threat detection.

### AI Security Agents
Gemini/OpenAI/Claude agent cards, API key configuration, and test URL analysis.

### URL Detail Modal
Click any URL for full stats: visits, unique pages, 30-day graph, browser breakdown, recent pages.

---

## ⚙️ How It Works

1. **Browser Detection** — Scans for Chrome, Safari, Edge, Brave, Firefox
2. **Data Reading** — Reads SQLite databases for history/bookmarks
3. **Threat Analysis** — Scores every URL (0-100 risk score)
4. **Network Monitoring** — Uses `lsof`/`netstat` for active connections
5. **AI Analysis** — Sends threats to AI agent for intelligent assessment
6. **Real-time Updates** — WebSocket pushes live browsing activity
7. **Extension** — Runs in-browser for per-page analysis and ad blocking

---

## 🔒 Privacy

- **100% local** — No data leaves your machine (except AI API calls if configured)
- **No telemetry** — Zero tracking or analytics
- **Your data stays yours** — All browser data is read directly from local files

---

## 📄 License

MIT License — feel free to use, modify, and distribute.

---

**Built with ❤️ by [Jalendar](https://github.com/Jalendar10)**
