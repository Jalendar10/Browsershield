#!/usr/bin/env node
/**
 * BrowserShield — Extension Installer
 * Opens Chrome/Edge/Brave extensions page and provides instructions
 * to load the unpacked extension automatically.
 */

const { execSync } = require('child_process');
const path = require('path');
const os = require('os');

const EXT_DIR = path.resolve(__dirname, '..', 'extension');
const PLATFORM = process.platform;

console.log('\n🛡️  BrowserShield — Browser Extension Installer\n');
console.log('━'.repeat(50));
console.log(`\n📁 Extension directory:\n   ${EXT_DIR}\n`);

// Detect which browsers to install into
const browsers = [];

if (PLATFORM === 'darwin') {
    const checks = [
        { name: 'Google Chrome', cmd: 'open -a "Google Chrome"', url: 'chrome://extensions' },
        { name: 'Microsoft Edge', cmd: 'open -a "Microsoft Edge"', url: 'edge://extensions' },
        { name: 'Brave Browser', cmd: 'open -a "Brave Browser"', url: 'brave://extensions' },
    ];

    for (const browser of checks) {
        try {
            // Check if app exists
            execSync(`mdfind "kMDItemCFBundleIdentifier == '*'" | grep -i "${browser.name.toLowerCase().replace(/ /g, '')}"`, { stdio: 'pipe' });
            browsers.push(browser);
        } catch {
            try {
                // Fallback check
                const apps = execSync('ls /Applications/', { encoding: 'utf8' });
                if (apps.includes(browser.name)) {
                    browsers.push(browser);
                }
            } catch { }
        }
    }
} else if (PLATFORM === 'win32') {
    browsers.push(
        { name: 'Google Chrome', url: 'chrome://extensions' },
        { name: 'Microsoft Edge', url: 'edge://extensions' },
        { name: 'Brave Browser', url: 'brave://extensions' }
    );
} else {
    browsers.push(
        { name: 'Google Chrome', url: 'chrome://extensions' },
        { name: 'Chromium', url: 'chrome://extensions' },
        { name: 'Brave Browser', url: 'brave://extensions' }
    );
}

console.log(`🌐 Detected browsers: ${browsers.map(b => b.name).join(', ')}\n`);

// Open extension pages
let opened = false;
for (const browser of browsers) {
    try {
        if (PLATFORM === 'darwin') {
            // Open the extensions page in the browser
            execSync(`open -a "${browser.name}" "${browser.url}"`, { stdio: 'pipe' });
            opened = true;
            console.log(`✅ Opened ${browser.name} extensions page`);
        } else if (PLATFORM === 'win32') {
            execSync(`start "" "${browser.url}"`, { stdio: 'pipe' });
            opened = true;
        } else {
            try {
                const cmd = browser.name.toLowerCase().replace(/ /g, '-');
                execSync(`${cmd} "${browser.url}" &`, { stdio: 'pipe' });
                opened = true;
            } catch { }
        }
    } catch (err) {
        console.log(`⚠️  Could not open ${browser.name}: ${err.message}`);
    }
}

// Print instructions
console.log('\n━'.repeat(50));
console.log('\n📋 To install the BrowserShield extension:\n');
console.log('   1. Enable "Developer mode" (toggle in top-right)');
console.log('   2. Click "Load unpacked"');
console.log(`   3. Select this folder:\n      ${EXT_DIR}`);
console.log('\n   The extension will appear in your toolbar with a 🛡️ shield icon.');
console.log('   Click it on any page to see real-time threat analysis!\n');

if (!opened) {
    console.log('   Alternatively, manually navigate to:\n');
    console.log('   Chrome: chrome://extensions');
    console.log('   Edge:   edge://extensions');
    console.log('   Brave:  brave://extensions');
    console.log('');
}

// Copy path to clipboard on macOS
if (PLATFORM === 'darwin') {
    try {
        execSync(`echo "${EXT_DIR}" | pbcopy`);
        console.log('📋 Extension path copied to clipboard!\n');
    } catch { }
}

console.log('━'.repeat(50) + '\n');
