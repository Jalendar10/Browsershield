/**
 * BrowserShield - Browser Detector
 * Detects which browsers are installed on the system and locates their data files.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const HOME = os.homedir();
const PLATFORM = process.platform;

/**
 * Browser path configurations per platform
 */
const BROWSER_CONFIGS = {
  darwin: {
    chrome: {
      name: 'Google Chrome',
      icon: 'chrome',
      history: path.join(HOME, 'Library/Application Support/Google/Chrome/Default/History'),
      bookmarks: path.join(HOME, 'Library/Application Support/Google/Chrome/Default/Bookmarks'),
      type: 'chromium'
    },
    safari: {
      name: 'Safari',
      icon: 'safari',
      history: path.join(HOME, 'Library/Safari/History.db'),
      bookmarks: path.join(HOME, 'Library/Safari/Bookmarks.plist'),
      type: 'safari'
    },
    firefox: {
      name: 'Firefox',
      icon: 'firefox',
      profilesDir: path.join(HOME, 'Library/Application Support/Firefox/Profiles'),
      type: 'firefox'
    },
    edge: {
      name: 'Microsoft Edge',
      icon: 'edge',
      history: path.join(HOME, 'Library/Application Support/Microsoft Edge/Default/History'),
      bookmarks: path.join(HOME, 'Library/Application Support/Microsoft Edge/Default/Bookmarks'),
      type: 'chromium'
    },
    brave: {
      name: 'Brave',
      icon: 'brave',
      history: path.join(HOME, 'Library/Application Support/BraveSoftware/Brave-Browser/Default/History'),
      bookmarks: path.join(HOME, 'Library/Application Support/BraveSoftware/Brave-Browser/Default/Bookmarks'),
      type: 'chromium'
    }
  },
  win32: {
    chrome: {
      name: 'Google Chrome',
      icon: 'chrome',
      history: path.join(process.env.LOCALAPPDATA || '', 'Google/Chrome/User Data/Default/History'),
      bookmarks: path.join(process.env.LOCALAPPDATA || '', 'Google/Chrome/User Data/Default/Bookmarks'),
      type: 'chromium'
    },
    edge: {
      name: 'Microsoft Edge',
      icon: 'edge',
      history: path.join(process.env.LOCALAPPDATA || '', 'Microsoft/Edge/User Data/Default/History'),
      bookmarks: path.join(process.env.LOCALAPPDATA || '', 'Microsoft/Edge/User Data/Default/Bookmarks'),
      type: 'chromium'
    },
    firefox: {
      name: 'Firefox',
      icon: 'firefox',
      profilesDir: path.join(process.env.APPDATA || '', 'Mozilla/Firefox/Profiles'),
      type: 'firefox'
    },
    brave: {
      name: 'Brave',
      icon: 'brave',
      history: path.join(process.env.LOCALAPPDATA || '', 'BraveSoftware/Brave-Browser/User Data/Default/History'),
      bookmarks: path.join(process.env.LOCALAPPDATA || '', 'BraveSoftware/Brave-Browser/User Data/Default/Bookmarks'),
      type: 'chromium'
    },
    opera: {
      name: 'Opera',
      icon: 'opera',
      history: path.join(process.env.APPDATA || '', 'Opera Software/Opera Stable/History'),
      bookmarks: path.join(process.env.APPDATA || '', 'Opera Software/Opera Stable/Bookmarks'),
      type: 'chromium'
    }
  },
  linux: {
    chrome: {
      name: 'Google Chrome',
      icon: 'chrome',
      history: path.join(HOME, '.config/google-chrome/Default/History'),
      bookmarks: path.join(HOME, '.config/google-chrome/Default/Bookmarks'),
      type: 'chromium'
    },
    firefox: {
      name: 'Firefox',
      icon: 'firefox',
      profilesDir: path.join(HOME, '.mozilla/firefox'),
      type: 'firefox'
    },
    chromium: {
      name: 'Chromium',
      icon: 'chromium',
      history: path.join(HOME, '.config/chromium/Default/History'),
      bookmarks: path.join(HOME, '.config/chromium/Default/Bookmarks'),
      type: 'chromium'
    },
    edge: {
      name: 'Microsoft Edge',
      icon: 'edge',
      history: path.join(HOME, '.config/microsoft-edge/Default/History'),
      bookmarks: path.join(HOME, '.config/microsoft-edge/Default/Bookmarks'),
      type: 'chromium'
    },
    brave: {
      name: 'Brave',
      icon: 'brave',
      history: path.join(HOME, '.config/BraveSoftware/Brave-Browser/Default/History'),
      bookmarks: path.join(HOME, '.config/BraveSoftware/Brave-Browser/Default/Bookmarks'),
      type: 'chromium'
    }
  }
};

/**
 * Resolve the Firefox default profile directory
 */
function resolveFirefoxProfile(profilesDir) {
  if (!fs.existsSync(profilesDir)) return null;

  const entries = fs.readdirSync(profilesDir);
  // Look for *.default-release first, then *.default
  let profile = entries.find(e => e.endsWith('.default-release'));
  if (!profile) profile = entries.find(e => e.endsWith('.default'));
  if (!profile && entries.length > 0) profile = entries[0];

  if (profile) {
    return path.join(profilesDir, profile);
  }
  return null;
}

/**
 * Detect all installed browsers and return their metadata
 */
function detectInstalledBrowsers() {
  const configs = BROWSER_CONFIGS[PLATFORM] || {};
  const browsers = [];

  for (const [key, config] of Object.entries(configs)) {
    const browser = {
      id: key,
      name: config.name,
      icon: config.icon,
      type: config.type,
      installed: false,
      historyPath: null,
      bookmarksPath: null
    };

    if (config.type === 'firefox') {
      const profileDir = resolveFirefoxProfile(config.profilesDir);
      if (profileDir) {
        const historyPath = path.join(profileDir, 'places.sqlite');
        if (fs.existsSync(historyPath)) {
          browser.installed = true;
          browser.historyPath = historyPath;
          browser.bookmarksPath = historyPath; // bookmarks are in the same DB
        }
      }
    } else if (config.type === 'safari') {
      if (fs.existsSync(config.history)) {
        browser.installed = true;
        browser.historyPath = config.history;
        browser.bookmarksPath = config.bookmarks;
      }
    } else {
      // Chromium-based
      if (fs.existsSync(config.history)) {
        browser.installed = true;
        browser.historyPath = config.history;
        browser.bookmarksPath = config.bookmarks;
      }
    }

    if (browser.installed) {
      browsers.push(browser);
    }
  }

  return browsers;
}

module.exports = { detectInstalledBrowsers, resolveFirefoxProfile };
