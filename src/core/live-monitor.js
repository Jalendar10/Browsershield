/**
 * BrowserShield - Live Activity Monitor
 * Watches browser history files for real-time changes and emits new activity events.
 */

const EventEmitter = require('events');
const { getRecentEntries } = require('./history-reader');

let chokidar;
try {
    chokidar = require('chokidar');
} catch (e) {
    console.error('chokidar not available, live monitoring disabled');
}

class LiveMonitor extends EventEmitter {
    constructor() {
        super();
        this.watchers = [];
        this.knownUrls = new Map(); // browser -> Set of known URL strings
        this.isRunning = false;
        this.pollInterval = null;
        this.browsers = [];
    }

    /**
     * Start monitoring all detected browsers for new activity
     */
    start(browsers) {
        if (this.isRunning) return;
        this.isRunning = true;
        this.browsers = browsers;

        // Initialize known URLs for each browser
        for (const browser of browsers) {
            if (!browser.installed || !browser.historyPath) continue;

            const recentEntries = getRecentEntries(browser, 60); // last 60 minutes
            const urlSet = new Set(recentEntries.map(e => e.url));
            this.knownUrls.set(browser.id, urlSet);

            // Watch the history file for changes
            if (chokidar) {
                try {
                    const watcher = chokidar.watch(browser.historyPath, {
                        persistent: true,
                        ignoreInitial: true,
                        awaitWriteFinish: {
                            stabilityThreshold: 1000,
                            pollInterval: 500
                        },
                        usePolling: true,
                        interval: 2000
                    });

                    watcher.on('change', () => {
                        this._checkForNewEntries(browser);
                    });

                    this.watchers.push(watcher);
                    console.log(`[LiveMonitor] Watching ${browser.name}: ${browser.historyPath}`);
                } catch (err) {
                    console.error(`[LiveMonitor] Failed to watch ${browser.name}:`, err.message);
                }
            }
        }

        // Also poll periodically as a backup (some OS/browser combos don't trigger file events reliably)
        this.pollInterval = setInterval(() => {
            for (const browser of this.browsers) {
                if (browser.installed && browser.historyPath) {
                    this._checkForNewEntries(browser);
                }
            }
        }, 5000); // every 5 seconds

        console.log(`[LiveMonitor] Started monitoring ${browsers.filter(b => b.installed).length} browser(s)`);
    }

    /**
     * Check a browser for new history entries since last check
     */
    _checkForNewEntries(browser) {
        try {
            const recentEntries = getRecentEntries(browser, 2); // last 2 minutes
            const knownSet = this.knownUrls.get(browser.id) || new Set();

            for (const entry of recentEntries) {
                const key = entry.url + '|' + entry.lastVisit?.toISOString();
                if (!knownSet.has(entry.url)) {
                    knownSet.add(entry.url);
                    this.emit('newActivity', entry);
                }
            }

            // Keep the known set bounded
            if (knownSet.size > 5000) {
                const arr = Array.from(knownSet);
                const trimmed = new Set(arr.slice(arr.length - 2000));
                this.knownUrls.set(browser.id, trimmed);
            } else {
                this.knownUrls.set(browser.id, knownSet);
            }
        } catch (err) {
            // Silently ignore read errors (browser might be writing)
        }
    }

    /**
     * Stop all watchers and timers
     */
    stop() {
        this.isRunning = false;

        for (const watcher of this.watchers) {
            watcher.close();
        }
        this.watchers = [];

        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }

        console.log('[LiveMonitor] Stopped');
    }

    /**
     * Get the recent activity feed (last N minutes)
     */
    getRecentActivity(minutes = 30) {
        const allRecent = [];
        for (const browser of this.browsers) {
            if (browser.installed && browser.historyPath) {
                const entries = getRecentEntries(browser, minutes);
                allRecent.push(...entries);
            }
        }
        allRecent.sort((a, b) => (b.lastVisit?.getTime() || 0) - (a.lastVisit?.getTime() || 0));
        return allRecent;
    }
}

module.exports = LiveMonitor;
