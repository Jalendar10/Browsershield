/**
 * BrowserShield - Process Monitor
 * Monitors browser processes for open/close events and active window detection.
 */

const EventEmitter = require('events');
const { execSync } = require('child_process');

const PLATFORM = process.platform;

/**
 * Browser process names by platform
 */
const BROWSER_PROCESSES = {
    darwin: {
        'Google Chrome': ['Google Chrome'],
        'Safari': ['Safari'],
        'Firefox': ['firefox'],
        'Microsoft Edge': ['Microsoft Edge'],
        'Brave': ['Brave Browser'],
        'Opera': ['Opera'],
        'Arc': ['Arc']
    },
    win32: {
        'Google Chrome': ['chrome.exe'],
        'Firefox': ['firefox.exe'],
        'Microsoft Edge': ['msedge.exe'],
        'Brave': ['brave.exe'],
        'Opera': ['opera.exe']
    },
    linux: {
        'Google Chrome': ['google-chrome', 'chrome'],
        'Firefox': ['firefox'],
        'Microsoft Edge': ['msedge', 'microsoft-edge'],
        'Brave': ['brave-browser', 'brave'],
        'Chromium': ['chromium', 'chromium-browser']
    }
};

class ProcessMonitor extends EventEmitter {
    constructor() {
        super();
        this.runningBrowsers = new Map(); // name -> true/false
        this.pollInterval = null;
        this.isRunning = false;
    }

    /**
     * Start polling for browser process changes
     */
    start(intervalMs = 3000) {
        if (this.isRunning) return;
        this.isRunning = true;

        // Initial snapshot
        this._checkProcesses();

        this.pollInterval = setInterval(() => {
            this._checkProcesses();
        }, intervalMs);

        console.log('[ProcessMonitor] Started watching browser processes');
    }

    /**
     * Check current running processes and emit events for changes
     */
    _checkProcesses() {
        try {
            const procs = this._getProcessNames();
            const browserConfig = BROWSER_PROCESSES[PLATFORM] || {};

            for (const [browserName, processNames] of Object.entries(browserConfig)) {
                const isRunning = processNames.some(pn =>
                    procs.some(p => p.toLowerCase().includes(pn.toLowerCase()))
                );

                const wasRunning = this.runningBrowsers.get(browserName) || false;

                if (isRunning && !wasRunning) {
                    this.runningBrowsers.set(browserName, true);
                    this.emit('browserOpened', {
                        browser: browserName,
                        timestamp: new Date().toISOString(),
                        type: 'opened'
                    });
                } else if (!isRunning && wasRunning) {
                    this.runningBrowsers.set(browserName, false);
                    this.emit('browserClosed', {
                        browser: browserName,
                        timestamp: new Date().toISOString(),
                        type: 'closed'
                    });
                } else {
                    this.runningBrowsers.set(browserName, isRunning);
                }
            }
        } catch (err) {
            // Silently ignore process check errors
        }
    }

    /**
     * Get list of running process names
     */
    _getProcessNames() {
        try {
            if (PLATFORM === 'darwin') {
                const output = execSync('ps -eo comm= 2>/dev/null | head -300', { encoding: 'utf-8', timeout: 3000 });
                return output.trim().split('\n');
            } else if (PLATFORM === 'win32') {
                const output = execSync('tasklist /fo csv /nh 2>nul', { encoding: 'utf-8', timeout: 3000 });
                return output.trim().split('\n').map(l => {
                    const m = l.match(/"([^"]+)"/);
                    return m ? m[1] : '';
                });
            } else {
                const output = execSync('ps -eo comm= 2>/dev/null | head -300', { encoding: 'utf-8', timeout: 3000 });
                return output.trim().split('\n');
            }
        } catch {
            return [];
        }
    }

    /**
     * Get the currently active browser window info (macOS only via AppleScript)
     */
    getActiveWindowInfo() {
        if (PLATFORM !== 'darwin') return null;

        try {
            // Try Chrome first
            const browsers = [
                { name: 'Google Chrome', script: 'tell application "Google Chrome" to get {URL of active tab of front window, title of active tab of front window}' },
                { name: 'Safari', script: 'tell application "Safari" to get {URL of current tab of front window, name of current tab of front window}' },
                { name: 'Brave', script: 'tell application "Brave Browser" to get {URL of active tab of front window, title of active tab of front window}' },
                { name: 'Microsoft Edge', script: 'tell application "Microsoft Edge" to get {URL of active tab of front window, title of active tab of front window}' }
            ];

            // Get the frontmost app
            const frontApp = execSync('osascript -e \'tell application "System Events" to get name of first application process whose frontmost is true\'', {
                encoding: 'utf-8', timeout: 2000
            }).trim();

            for (const b of browsers) {
                if (frontApp.toLowerCase().includes(b.name.toLowerCase().split(' ')[0])) {
                    try {
                        const result = execSync(`osascript -e '${b.script}' 2>/dev/null`, {
                            encoding: 'utf-8', timeout: 2000
                        }).trim();
                        const parts = result.split(', ');
                        if (parts.length >= 2) {
                            return {
                                browser: b.name,
                                url: parts[0],
                                title: parts.slice(1).join(', '),
                                timestamp: new Date().toISOString()
                            };
                        }
                    } catch { /* browser not active */ }
                }
            }
        } catch {
            return null;
        }
        return null;
    }

    /**
     * Get currently running browsers
     */
    getRunningBrowsers() {
        const running = [];
        for (const [name, isRunning] of this.runningBrowsers) {
            if (isRunning) running.push(name);
        }
        return running;
    }

    /**
     * Stop monitoring
     */
    stop() {
        this.isRunning = false;
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        console.log('[ProcessMonitor] Stopped');
    }
}

module.exports = ProcessMonitor;
