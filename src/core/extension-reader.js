/**
 * BrowserShield - Browser Extensions Reader
 * Detects installed extensions in Chrome, Edge, Brave, and Firefox.
 * Reads manifest.json / extensions.json and flags risky permissions.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const HOME = os.homedir();
const PLATFORM = process.platform;

/**
 * Permissions that indicate potential security risk
 */
const RISKY_PERMISSIONS = new Set([
    '<all_urls>', '*://*/*', 'http://*/*', 'https://*/*',
    'webRequest', 'webRequestBlocking', 'webNavigation',
    'cookies', 'tabs', 'activeTab', 'history', 'bookmarks',
    'browsingData', 'clipboardRead', 'clipboardWrite',
    'contentSettings', 'debugger', 'declarativeNetRequest',
    'downloads', 'geolocation', 'management', 'nativeMessaging',
    'pageCapture', 'privacy', 'proxy', 'storage',
    'tabCapture', 'topSites', 'webRequestAuthProvider'
]);

/**
 * Classify permission risk level
 */
function classifyPermissionRisk(permissions) {
    if (!permissions || permissions.length === 0) return 'safe';
    const risky = permissions.filter(p => RISKY_PERMISSIONS.has(p));
    if (risky.some(p => ['<all_urls>', '*://*/*', 'webRequest', 'webRequestBlocking', 'debugger', 'nativeMessaging'].includes(p))) return 'high';
    if (risky.length >= 3) return 'medium';
    if (risky.length > 0) return 'low';
    return 'safe';
}

/**
 * Get Chromium extension directories per platform
 */
function getChromiumExtensionPaths() {
    const browsers = {};
    if (PLATFORM === 'darwin') {
        browsers.chrome = path.join(HOME, 'Library/Application Support/Google/Chrome/Default/Extensions');
        browsers.edge = path.join(HOME, 'Library/Application Support/Microsoft Edge/Default/Extensions');
        browsers.brave = path.join(HOME, 'Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions');
    } else if (PLATFORM === 'win32') {
        const local = process.env.LOCALAPPDATA || '';
        browsers.chrome = path.join(local, 'Google/Chrome/User Data/Default/Extensions');
        browsers.edge = path.join(local, 'Microsoft/Edge/User Data/Default/Extensions');
        browsers.brave = path.join(local, 'BraveSoftware/Brave-Browser/User Data/Default/Extensions');
    } else {
        browsers.chrome = path.join(HOME, '.config/google-chrome/Default/Extensions');
        browsers.edge = path.join(HOME, '.config/microsoft-edge/Default/Extensions');
        browsers.brave = path.join(HOME, '.config/BraveSoftware/Brave-Browser/Default/Extensions');
    }
    return browsers;
}

/**
 * Read extensions from a Chromium-based browser
 */
function readChromiumExtensions(extDir, browserName) {
    if (!fs.existsSync(extDir)) return [];
    const extensions = [];

    try {
        const extIds = fs.readdirSync(extDir).filter(f => {
            const full = path.join(extDir, f);
            return fs.statSync(full).isDirectory() && f !== 'Temp';
        });

        for (const extId of extIds) {
            const extPath = path.join(extDir, extId);
            try {
                // Each extension ID has version subdirectories
                const versions = fs.readdirSync(extPath).filter(v => {
                    return fs.statSync(path.join(extPath, v)).isDirectory();
                });

                if (versions.length === 0) continue;
                // Use the latest version
                const latestVersion = versions.sort().pop();
                const manifestPath = path.join(extPath, latestVersion, 'manifest.json');

                if (!fs.existsSync(manifestPath)) continue;

                const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
                const allPermissions = [
                    ...(manifest.permissions || []),
                    ...(manifest.optional_permissions || []),
                    ...(manifest.host_permissions || [])
                ];

                const riskyPerms = allPermissions.filter(p => RISKY_PERMISSIONS.has(p));
                const riskLevel = classifyPermissionRisk(allPermissions);

                extensions.push({
                    id: extId,
                    name: manifest.name || extId,
                    version: manifest.version || latestVersion,
                    description: manifest.description || '',
                    browser: browserName,
                    browserIcon: browserName.toLowerCase().replace(/\s+/g, '').replace('google', '').replace('microsoft', ''),
                    permissions: allPermissions,
                    riskyPermissions: riskyPerms,
                    riskLevel,
                    manifestVersion: manifest.manifest_version || 2,
                    hasContentScripts: !!(manifest.content_scripts && manifest.content_scripts.length > 0),
                    hasBackgroundPage: !!(manifest.background)
                });
            } catch {
                // Skip malformed extensions
            }
        }
    } catch (err) {
        console.error(`Error reading ${browserName} extensions:`, err.message);
    }

    return extensions;
}

/**
 * Read Firefox extensions from extensions.json
 */
function readFirefoxExtensions() {
    const extensions = [];
    let profilesDir;

    if (PLATFORM === 'darwin') {
        profilesDir = path.join(HOME, 'Library/Application Support/Firefox/Profiles');
    } else if (PLATFORM === 'win32') {
        profilesDir = path.join(process.env.APPDATA || '', 'Mozilla/Firefox/Profiles');
    } else {
        profilesDir = path.join(HOME, '.mozilla/firefox');
    }

    if (!fs.existsSync(profilesDir)) return [];

    try {
        const profiles = fs.readdirSync(profilesDir);
        let profile = profiles.find(p => p.endsWith('.default-release'));
        if (!profile) profile = profiles.find(p => p.endsWith('.default'));
        if (!profile && profiles.length > 0) profile = profiles[0];

        if (!profile) return [];

        const extJsonPath = path.join(profilesDir, profile, 'extensions.json');
        if (!fs.existsSync(extJsonPath)) return [];

        const data = JSON.parse(fs.readFileSync(extJsonPath, 'utf-8'));
        const addons = data.addons || [];

        for (const addon of addons) {
            if (addon.type !== 'extension') continue;
            if (addon.location === 'app-system-defaults') continue; // Skip built-in

            const permissions = addon.userPermissions?.permissions || [];
            const origins = addon.userPermissions?.origins || [];
            const allPerms = [...permissions, ...origins];
            const riskyPerms = allPerms.filter(p => RISKY_PERMISSIONS.has(p));

            extensions.push({
                id: addon.id || '',
                name: addon.defaultLocale?.name || addon.id || 'Unknown',
                version: addon.version || '',
                description: addon.defaultLocale?.description || '',
                browser: 'Firefox',
                browserIcon: 'firefox',
                permissions: allPerms,
                riskyPermissions: riskyPerms,
                riskLevel: classifyPermissionRisk(allPerms),
                manifestVersion: 2,
                active: addon.active !== false,
                hasContentScripts: false,
                hasBackgroundPage: false
            });
        }
    } catch (err) {
        console.error('Error reading Firefox extensions:', err.message);
    }

    return extensions;
}

/**
 * Read all browser extensions
 */
function readAllExtensions() {
    const all = [];
    const chromiumPaths = getChromiumExtensionPaths();
    const browserNames = { chrome: 'Google Chrome', edge: 'Microsoft Edge', brave: 'Brave' };

    for (const [key, extDir] of Object.entries(chromiumPaths)) {
        const exts = readChromiumExtensions(extDir, browserNames[key] || key);
        all.push(...exts);
    }

    const ffExts = readFirefoxExtensions();
    all.push(...ffExts);

    // Filter out Chrome built-in extensions with no real name
    return all.filter(ext => {
        const name = ext.name || '';
        if (name.startsWith('__MSG_')) return true; // Localized names are fine
        if (!name || name.length < 2) return false;
        return true;
    });
}

/**
 * Get extension stats
 */
function getExtensionStats(extensions) {
    const stats = { total: extensions.length, safe: 0, low: 0, medium: 0, high: 0, byBrowser: {} };
    for (const ext of extensions) {
        stats[ext.riskLevel] = (stats[ext.riskLevel] || 0) + 1;
        stats.byBrowser[ext.browser] = (stats.byBrowser[ext.browser] || 0) + 1;
    }
    return stats;
}

module.exports = { readAllExtensions, readChromiumExtensions, readFirefoxExtensions, getExtensionStats, classifyPermissionRisk };
