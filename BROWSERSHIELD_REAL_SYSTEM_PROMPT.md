# 🛡️ BROWSERSHIELD - REAL SYSTEM BROWSER SECURITY MONITOR

## PROMPT FOR AI ASSISTANT (Claude/GPT/Gemini)

---

### SYSTEM PROMPT

```
You are building a REAL browser security monitoring application called BrowserShield.

This is NOT a demo with fake data. This application must:

1. READ ACTUAL BROWSER HISTORY from the user's installed browsers
2. READ ACTUAL BOOKMARKS from all browsers
3. MONITOR CURRENTLY OPEN TABS in real-time
4. ANALYZE REAL URLs for threats
5. SHOW LIVE ACTIVITY as the user browses

The application runs locally on the user's machine and accesses real browser data files.

CRITICAL REQUIREMENTS:
- Must detect which browsers are installed on the system
- Must read SQLite databases for Chrome/Edge/Brave history
- Must read Firefox places.sqlite for Firefox history
- Must read Safari History.db for Safari history
- Must show REAL bookmarks from all browsers
- Must monitor file system changes for live updates
- Must work on Windows, macOS, and Linux
```

---

## ARCHITECTURE DESIGN

### System Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        BROWSERSHIELD ARCHITECTURE                           │
│                     (Real System Integration)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    BROWSER DATA LAYER                                 │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐        │  │
│  │  │  Chrome    │ │  Firefox   │ │   Edge     │ │  Safari    │        │  │
│  │  │  History   │ │  History   │ │  History   │ │  History   │        │  │
│  │  │  SQLite    │ │  SQLite    │ │  SQLite    │ │  SQLite    │        │  │
│  │  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └─────┬──────┘        │  │
│  │        │              │              │              │                │  │
│  │        └──────────────┴──────────────┴──────────────┘                │  │
│  │                              │                                        │  │
│  └──────────────────────────────┼────────────────────────────────────────┘  │
│                                 ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    DATA COLLECTION ENGINE                             │  │
│  │  • Browser Detection (which browsers installed)                       │  │
│  │  • History Reader (SQLite parser)                                     │  │
│  │  • Bookmark Extractor (JSON/SQLite)                                   │  │
│  │  • File Watcher (real-time history updates)                          │  │
│  │  • Active Tab Monitor (OS-level window detection)                     │  │
│  └──────────────────────────────┬────────────────────────────────────────┘  │
│                                 │                                           │
│                                 ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    AI THREAT ANALYSIS ENGINE                          │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐    │  │
│  │  │ PhishGuard  │ │ Malware    │ │ Payment    │ │ Network     │     │  │
│  │  │ Agent       │ │ Hunter     │ │ Sentinel   │ │ Watcher     │     │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘    │  │
│  └──────────────────────────────┬────────────────────────────────────────┘  │
│                                 │                                           │
│                                 ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    ELECTRON/TAURI DESKTOP APP                         │  │
│  │  • Real-time Dashboard                                                │  │
│  │  • Live Activity Stream (actual browsing)                             │  │
│  │  • Browser History View (categorized by browser)                      │  │
│  │  • Bookmark Analysis                                                  │  │
│  │  • Threat Alerts                                                      │  │
│  │  • System Tray Integration                                            │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## BROWSER DATA LOCATIONS

### Windows

```javascript
const BROWSER_PATHS_WINDOWS = {
  chrome: {
    history: '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History',
    bookmarks: '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Bookmarks',
    currentTabs: '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Current Tabs'
  },
  edge: {
    history: '%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History',
    bookmarks: '%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Bookmarks',
    currentTabs: '%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Current Tabs'
  },
  firefox: {
    profiles: '%APPDATA%\\Mozilla\\Firefox\\Profiles',
    // Each profile has: places.sqlite (history + bookmarks)
  },
  brave: {
    history: '%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History',
    bookmarks: '%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Bookmarks'
  },
  opera: {
    history: '%APPDATA%\\Opera Software\\Opera Stable\\History',
    bookmarks: '%APPDATA%\\Opera Software\\Opera Stable\\Bookmarks'
  }
};
```

### macOS

```javascript
const BROWSER_PATHS_MACOS = {
  chrome: {
    history: '~/Library/Application Support/Google/Chrome/Default/History',
    bookmarks: '~/Library/Application Support/Google/Chrome/Default/Bookmarks'
  },
  safari: {
    history: '~/Library/Safari/History.db',
    bookmarks: '~/Library/Safari/Bookmarks.plist'
  },
  firefox: {
    profiles: '~/Library/Application Support/Firefox/Profiles'
  },
  edge: {
    history: '~/Library/Application Support/Microsoft Edge/Default/History',
    bookmarks: '~/Library/Application Support/Microsoft Edge/Default/Bookmarks'
  },
  brave: {
    history: '~/Library/Application Support/BraveSoftware/Brave-Browser/Default/History',
    bookmarks: '~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Bookmarks'
  }
};
```

### Linux

```javascript
const BROWSER_PATHS_LINUX = {
  chrome: {
    history: '~/.config/google-chrome/Default/History',
    bookmarks: '~/.config/google-chrome/Default/Bookmarks'
  },
  firefox: {
    profiles: '~/.mozilla/firefox'
  },
  chromium: {
    history: '~/.config/chromium/Default/History',
    bookmarks: '~/.config/chromium/Default/Bookmarks'
  },
  edge: {
    history: '~/.config/microsoft-edge/Default/History',
    bookmarks: '~/.config/microsoft-edge/Default/Bookmarks'
  },
  brave: {
    history: '~/.config/BraveSoftware/Brave-Browser/Default/History',
    bookmarks: '~/.config/BraveSoftware/Brave-Browser/Default/Bookmarks'
  }
};
```

---

## CORE MODULES TO IMPLEMENT

### 1. Browser Detector

```javascript
// Detect which browsers are installed on the system
async function detectInstalledBrowsers() {
  const browsers = [];
  const platform = process.platform;
  
  // Check each browser path
  // Return array of { name, version, profilePath, isDefault }
  
  return browsers;
}
```

### 2. History Reader (SQLite)

```javascript
// Read Chrome/Edge/Brave history (Chromium-based)
async function readChromiumHistory(historyDbPath, days = 30) {
  // Copy database to temp (avoid lock issues)
  // Open with better-sqlite3 or sql.js
  // Query: SELECT url, title, visit_count, last_visit_time FROM urls
  // Convert Chrome timestamp to JS Date
  // Return array of { url, title, visitCount, lastVisit, browser }
}

// Read Firefox history
async function readFirefoxHistory(placesDbPath, days = 30) {
  // Query: SELECT url, title, visit_count, last_visit_date FROM moz_places
  // Return array of history entries
}

// Read Safari history (macOS)
async function readSafariHistory(historyDbPath, days = 30) {
  // Query: SELECT url, title FROM history_items JOIN history_visits
  // Return array of history entries
}
```

### 3. Bookmark Reader

```javascript
// Read Chromium bookmarks (JSON file)
async function readChromiumBookmarks(bookmarksPath) {
  const data = JSON.parse(fs.readFileSync(bookmarksPath));
  // Parse bookmark_bar, other, synced folders
  // Return flat array of { name, url, folder, dateAdded }
}

// Read Firefox bookmarks (SQLite)
async function readFirefoxBookmarks(placesDbPath) {
  // Query: SELECT title, url FROM moz_bookmarks JOIN moz_places
  // Return array of bookmarks
}
```

### 4. Live Activity Monitor

```javascript
// Watch for real-time history updates
class LiveActivityMonitor {
  constructor() {
    this.watchers = [];
    this.callbacks = [];
  }
  
  startWatching(browserPaths) {
    // Use chokidar or fs.watch to monitor history files
    // When file changes, read new entries
    // Emit events for new URLs visited
  }
  
  onNewActivity(callback) {
    this.callbacks.push(callback);
  }
}
```

### 5. Active Tab Detector (OS-Level)

```javascript
// Get currently active browser window/tab
// Windows: Use powershell or node-window-manager
// macOS: Use AppleScript or accessibility APIs
// Linux: Use xdotool or wmctrl

async function getActiveWindowInfo() {
  // Returns: { browser, url, title, timestamp }
}
```

---

## ELECTRON APP STRUCTURE

```
browsershield-desktop/
├── package.json
├── electron/
│   ├── main.js              # Electron main process
│   ├── preload.js           # Bridge to renderer
│   └── ipc-handlers.js      # IPC communication
├── src/
│   ├── core/
│   │   ├── browser-detector.js
│   │   ├── history-reader.js
│   │   ├── bookmark-reader.js
│   │   ├── live-monitor.js
│   │   └── threat-analyzer.js
│   ├── agents/
│   │   ├── phish-guard.js
│   │   ├── malware-hunter.js
│   │   ├── payment-sentinel.js
│   │   └── network-watcher.js
│   └── ui/
│       ├── App.jsx
│       ├── components/
│       │   ├── LiveActivityStream.jsx
│       │   ├── BrowserHistoryPanel.jsx
│       │   ├── BookmarkAnalyzer.jsx
│       │   ├── ThreatDashboard.jsx
│       │   └── AgentStatus.jsx
│       └── styles/
├── assets/
│   └── icons/
└── build/
```

---

## KEY FEATURES TO IMPLEMENT

### 1. LIVE ACTIVITY STREAM (Real Data)

```jsx
// Shows ACTUAL URLs as user browses
<LiveActivityStream>
  - Real-time URL detection
  - Browser icon for each entry
  - Timestamp
  - Threat level indicator
  - Auto-scrolling feed
</LiveActivityStream>
```

### 2. BROWSER HISTORY PANEL

```jsx
// Shows REAL history from installed browsers
<BrowserHistoryPanel>
  - Tabs for each browser (Chrome, Firefox, Edge, etc.)
  - Search/filter functionality
  - Date range selector
  - Risk highlighting
  - Export capability
</BrowserHistoryPanel>
```

### 3. BOOKMARK ANALYZER

```jsx
// Analyzes REAL bookmarks for threats
<BookmarkAnalyzer>
  - All bookmarks from all browsers
  - Categorized by folder
  - Dead link detection
  - Phishing bookmark detection
  - Duplicate finder
</BookmarkAnalyzer>
```

### 4. CURRENTLY OPEN TABS

```jsx
// Shows REAL currently open tabs
<OpenTabsMonitor>
  - All open browser windows
  - All tabs in each window
  - Real-time URL of active tab
  - Memory usage per tab
  - Threat scanning
</OpenTabsMonitor>
```

---

## IMPLEMENTATION CHECKLIST

### Phase 1: Core Data Access
- [ ] Browser detection module
- [ ] Chrome history reader
- [ ] Firefox history reader
- [ ] Edge history reader
- [ ] Safari history reader (macOS)
- [ ] Brave history reader
- [ ] Bookmark readers for all browsers

### Phase 2: Real-time Monitoring
- [ ] File watcher for history DBs
- [ ] Active window detector
- [ ] New URL event emitter
- [ ] WebSocket for live updates

### Phase 3: Threat Analysis
- [ ] URL risk scoring
- [ ] Phishing detection
- [ ] Typosquatting detection
- [ ] Malware domain checking
- [ ] SSL verification

### Phase 4: Desktop App
- [ ] Electron/Tauri setup
- [ ] System tray integration
- [ ] Native notifications
- [ ] Auto-start option
- [ ] Minimal resource usage

### Phase 5: Dashboard UI
- [ ] Live activity stream
- [ ] Browser-wise history view
- [ ] Bookmark analysis
- [ ] Open tabs monitor
- [ ] Threat alerts
- [ ] Statistics & charts

---

## SAMPLE DATA FLOW

```
User opens Chrome → Visits website
          │
          ▼
Chrome writes to History SQLite DB
          │
          ▼
BrowserShield File Watcher detects change
          │
          ▼
History Reader extracts new URL
          │
          ▼
Threat Analyzer scans URL
          │
          ├── Safe → Log to activity stream (green)
          │
          └── Threat → Alert user (red) + Log + Block option
          │
          ▼
Dashboard updates in real-time via WebSocket/IPC
```

---

## SECURITY & PRIVACY NOTES

1. **All data stays LOCAL** - No cloud upload
2. **Read-only access** - Never modifies browser data
3. **User consent** - Clear permissions on first run
4. **Encryption** - Local threat DB is encrypted
5. **No tracking** - Zero telemetry
6. **Open source** - Full transparency

---

## TECH STACK RECOMMENDATION

| Component | Technology |
|-----------|------------|
| Desktop Framework | Electron or Tauri |
| Backend | Node.js |
| Database Access | better-sqlite3 or sql.js |
| File Watching | chokidar |
| UI Framework | React + TailwindCSS |
| State Management | Zustand or Redux |
| IPC | Electron IPC or Tauri commands |
| Notifications | electron-notifier |
| System Tray | Electron Tray API |

---

## COMMANDS TO BUILD

```bash
# Create Electron app
npx create-electron-app browsershield-desktop --template=webpack-typescript

# Add dependencies
npm install better-sqlite3 chokidar electron-store electron-notifier

# For React UI
npm install react react-dom @types/react tailwindcss lucide-react recharts

# Build
npm run make
```

---

This document provides the complete blueprint for building a REAL browser security monitoring application that reads ACTUAL browser data from the user's system.
