/**
 * BrowserShield - App Monitor
 * Detects installed applications and running processes on the system.
 * Supports macOS, Windows, and Linux.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PLATFORM = process.platform;

/**
 * App categories by keyword matching
 */
const CATEGORIES = {
    browser: ['chrome', 'firefox', 'safari', 'edge', 'brave', 'opera', 'vivaldi', 'arc', 'tor browser', 'chromium'],
    development: ['xcode', 'visual studio', 'android studio', 'intellij', 'webstorm', 'pycharm', 'sublime', 'atom', 'terminal', 'iterm', 'docker', 'postman', 'github', 'git', 'node', 'python', 'java', 'cmake', 'cursor', 'warp'],
    productivity: ['microsoft', 'office', 'word', 'excel', 'powerpoint', 'keynote', 'pages', 'numbers', 'notion', 'obsidian', 'evernote', 'onenote', 'todoist', 'things', 'calendar', 'reminders', 'notes'],
    communication: ['slack', 'discord', 'zoom', 'teams', 'skype', 'telegram', 'whatsapp', 'signal', 'messenger', 'facetime', 'mail', 'outlook', 'thunderbird', 'messages'],
    media: ['spotify', 'music', 'vlc', 'quicktime', 'photos', 'preview', 'gimp', 'photoshop', 'figma', 'sketch', 'canva', 'audacity', 'garageband', 'imovie', 'final cut', 'premiere', 'obs', 'netflix', 'youtube', 'plex', 'infuse'],
    security: ['1password', 'lastpass', 'bitwarden', 'keychain', 'norton', 'malwarebytes', 'avast', 'kaspersky', 'little snitch', 'lulu', 'vpn', 'wireguard', 'tunnelblick', 'expressvpn', 'nordvpn'],
    social: ['twitter', 'instagram', 'facebook', 'tiktok', 'reddit', 'linkedin', 'snapchat', 'pinterest'],
    utilities: ['finder', 'activity monitor', 'disk utility', 'system preferences', 'system settings', 'appcleaner', 'the unarchiver', 'amphetamine', 'rectangle', 'magnet', 'alfred', 'raycast', 'bartender', 'cleanmymac', 'bettertouchtool'],
    cloud: ['dropbox', 'google drive', 'onedrive', 'icloud', 'box', 'mega'],
    gaming: ['steam', 'epic games', 'roblox', 'minecraft', 'league', 'valorant', 'genshin', 'battle.net']
};

/**
 * Categorize an app by its name
 */
function categorizeApp(appName) {
    const lower = appName.toLowerCase();
    for (const [category, keywords] of Object.entries(CATEGORIES)) {
        for (const kw of keywords) {
            if (lower.includes(kw)) return category;
        }
    }
    return 'other';
}

/**
 * Get category emoji
 */
function getCategoryEmoji(category) {
    const emojis = {
        browser: '🌐', development: '💻', productivity: '📊', communication: '💬',
        media: '🎵', security: '🔒', social: '📱', utilities: '🔧',
        cloud: '☁️', gaming: '🎮', other: '📦'
    };
    return emojis[category] || '📦';
}

/**
 * List installed applications on macOS
 */
function getInstalledAppsMacOS() {
    const apps = [];

    // Method 1: Read /Applications directory
    try {
        const appDirs = ['/Applications', path.join(os.homedir(), 'Applications')];
        for (const dir of appDirs) {
            if (!fs.existsSync(dir)) continue;
            const entries = fs.readdirSync(dir);
            for (const entry of entries) {
                if (entry.endsWith('.app')) {
                    const name = entry.replace('.app', '');
                    const appPath = path.join(dir, entry);
                    let version = '';
                    try {
                        const plistPath = path.join(appPath, 'Contents', 'Info.plist');
                        if (fs.existsSync(plistPath)) {
                            const versionStr = execSync(`/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "${plistPath}" 2>/dev/null || echo ""`, { encoding: 'utf-8' }).trim();
                            version = versionStr;
                        }
                    } catch { /* skip */ }

                    const category = categorizeApp(name);
                    apps.push({
                        name,
                        path: appPath,
                        version: version || 'Unknown',
                        category,
                        categoryEmoji: getCategoryEmoji(category),
                        source: dir === '/Applications' ? 'system' : 'user'
                    });
                }
            }
        }
    } catch (err) {
        console.error('Error reading Applications:', err.message);
    }

    apps.sort((a, b) => a.name.localeCompare(b.name));
    return apps;
}

/**
 * List installed applications on Windows
 */
function getInstalledAppsWindows() {
    try {
        const output = execSync('wmic product get name,version /format:csv', { encoding: 'utf-8', timeout: 15000 });
        const lines = output.trim().split('\n').slice(1);
        return lines.map(line => {
            const parts = line.split(',');
            const name = (parts[1] || '').trim();
            const version = (parts[2] || '').trim();
            if (!name) return null;
            const category = categorizeApp(name);
            return { name, path: '', version, category, categoryEmoji: getCategoryEmoji(category), source: 'system' };
        }).filter(Boolean);
    } catch {
        return [];
    }
}

/**
 * List installed applications on Linux
 */
function getInstalledAppsLinux() {
    const apps = [];
    try {
        // Try dpkg first (Debian/Ubuntu)
        const output = execSync('dpkg --list 2>/dev/null | grep "^ii" | head -200', { encoding: 'utf-8', timeout: 10000 });
        const lines = output.trim().split('\n');
        for (const line of lines) {
            const parts = line.split(/\s+/);
            if (parts.length >= 3) {
                const name = parts[1];
                const version = parts[2];
                const category = categorizeApp(name);
                apps.push({ name, path: '', version, category, categoryEmoji: getCategoryEmoji(category), source: 'dpkg' });
            }
        }
    } catch {
        try {
            // Fallback: flatpak
            const output = execSync('flatpak list --app 2>/dev/null', { encoding: 'utf-8', timeout: 10000 });
            const lines = output.trim().split('\n');
            for (const line of lines) {
                const parts = line.split('\t');
                if (parts.length >= 2) {
                    const name = parts[0];
                    const category = categorizeApp(name);
                    apps.push({ name, path: '', version: parts[2] || '', category, categoryEmoji: getCategoryEmoji(category), source: 'flatpak' });
                }
            }
        } catch { /* no package manager found */ }
    }
    return apps;
}

/**
 * Get all installed applications (cross-platform)
 */
function getInstalledApps() {
    switch (PLATFORM) {
        case 'darwin': return getInstalledAppsMacOS();
        case 'win32': return getInstalledAppsWindows();
        case 'linux': return getInstalledAppsLinux();
        default: return [];
    }
}

/**
 * Get currently running processes (returns app names)
 */
function getRunningApps() {
    try {
        if (PLATFORM === 'darwin') {
            const output = execSync('ps aux | grep -i ".app/Contents" | grep -v grep', { encoding: 'utf-8', timeout: 5000 });
            const apps = new Set();
            for (const line of output.split('\n')) {
                const match = line.match(/\/([^/]+)\.app\//);
                if (match) apps.add(match[1]);
            }
            return Array.from(apps);
        } else if (PLATFORM === 'win32') {
            const output = execSync('tasklist /fo csv /nh', { encoding: 'utf-8', timeout: 5000 });
            const apps = new Set();
            for (const line of output.split('\n')) {
                const match = line.match(/"([^"]+\.exe)"/);
                if (match) apps.add(match[1].replace('.exe', ''));
            }
            return Array.from(apps);
        } else {
            const output = execSync('ps -eo comm= | sort -u | head -100', { encoding: 'utf-8', timeout: 5000 });
            return output.trim().split('\n').map(s => s.trim()).filter(Boolean);
        }
    } catch {
        return [];
    }
}

/**
 * Get app stats summary
 */
function getAppStats(apps) {
    const categories = {};
    for (const app of apps) {
        categories[app.category] = (categories[app.category] || 0) + 1;
    }
    return { total: apps.length, categories, running: getRunningApps().length };
}

module.exports = { getInstalledApps, getRunningApps, getAppStats, categorizeApp, getCategoryEmoji };
