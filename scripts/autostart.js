#!/usr/bin/env node
/**
 * BrowserShield — Auto-Start Setup
 * Creates a LaunchAgent (macOS), Startup shortcut (Windows), or systemd service (Linux)
 * so BrowserShield starts automatically when you log in.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const PLATFORM = process.platform;
const HOME = os.homedir();
const PROJECT_DIR = path.resolve(__dirname);
const NODE_PATH = process.execPath;
const SERVER_SCRIPT = path.join(PROJECT_DIR, 'server.js');

function setupMacOS() {
    const agentDir = path.join(HOME, 'Library', 'LaunchAgents');
    const plistName = 'com.browsershield.monitor.plist';
    const plistPath = path.join(agentDir, plistName);

    if (!fs.existsSync(agentDir)) {
        fs.mkdirSync(agentDir, { recursive: true });
    }

    const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.browsershield.monitor</string>
  <key>ProgramArguments</key>
  <array>
    <string>${NODE_PATH}</string>
    <string>${SERVER_SCRIPT}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
  <key>WorkingDirectory</key>
  <string>${PROJECT_DIR}</string>
  <key>StandardOutPath</key>
  <string>${path.join(PROJECT_DIR, 'browsershield.log')}</string>
  <key>StandardErrorPath</key>
  <string>${path.join(PROJECT_DIR, 'browsershield-error.log')}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin</string>
  </dict>
</dict>
</plist>`;

    fs.writeFileSync(plistPath, plistContent);
    console.log(`✅ LaunchAgent created: ${plistPath}`);

    // Load it
    try {
        execSync(`launchctl load ${plistPath}`, { stdio: 'inherit' });
        console.log('✅ BrowserShield will start automatically on login');
    } catch {
        console.log('⚠️  LaunchAgent created but could not be loaded. It will activate on next login.');
    }
}

function setupWindows() {
    const startupDir = path.join(process.env.APPDATA || '', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
    const batPath = path.join(startupDir, 'BrowserShield.bat');

    const batContent = `@echo off
cd /d "${PROJECT_DIR}"
start /min "" "${NODE_PATH}" "${SERVER_SCRIPT}"
`;

    fs.writeFileSync(batPath, batContent);
    console.log(`✅ Startup script created: ${batPath}`);
    console.log('✅ BrowserShield will start automatically on login');
}

function setupLinux() {
    const serviceDir = path.join(HOME, '.config', 'systemd', 'user');
    const servicePath = path.join(serviceDir, 'browsershield.service');

    if (!fs.existsSync(serviceDir)) {
        fs.mkdirSync(serviceDir, { recursive: true });
    }

    const serviceContent = `[Unit]
Description=BrowserShield Security Monitor
After=default.target

[Service]
WorkingDirectory=${PROJECT_DIR}
ExecStart=${NODE_PATH} ${SERVER_SCRIPT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`;

    fs.writeFileSync(servicePath, serviceContent);

    try {
        execSync('systemctl --user daemon-reload', { stdio: 'inherit' });
        execSync('systemctl --user enable browsershield.service', { stdio: 'inherit' });
        console.log(`✅ Systemd service created: ${servicePath}`);
        console.log('✅ BrowserShield will start automatically on login');
    } catch {
        console.log(`✅ Service file created: ${servicePath}`);
        console.log('⚠️  Run: systemctl --user enable browsershield.service');
    }
}

function uninstall() {
    if (PLATFORM === 'darwin') {
        const plistPath = path.join(HOME, 'Library', 'LaunchAgents', 'com.browsershield.monitor.plist');
        try { execSync(`launchctl unload ${plistPath}`); } catch { }
        try { fs.unlinkSync(plistPath); } catch { }
        console.log('✅ LaunchAgent removed');
    } else if (PLATFORM === 'win32') {
        const batPath = path.join(process.env.APPDATA || '', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'BrowserShield.bat');
        try { fs.unlinkSync(batPath); } catch { }
        console.log('✅ Startup script removed');
    } else {
        try {
            execSync('systemctl --user disable browsershield.service', { stdio: 'inherit' });
            execSync('systemctl --user stop browsershield.service', { stdio: 'inherit' });
        } catch { }
        const servicePath = path.join(HOME, '.config', 'systemd', 'user', 'browsershield.service');
        try { fs.unlinkSync(servicePath); } catch { }
        console.log('✅ Systemd service removed');
    }
}

// Main
const args = process.argv.slice(2);
if (args.includes('--uninstall') || args.includes('--remove')) {
    console.log('\n🛡️  BrowserShield — Removing auto-start...\n');
    uninstall();
} else {
    console.log('\n🛡️  BrowserShield — Setting up auto-start...\n');
    console.log(`   Platform: ${PLATFORM}`);
    console.log(`   Node: ${NODE_PATH}`);
    console.log(`   Server: ${SERVER_SCRIPT}\n`);

    switch (PLATFORM) {
        case 'darwin': setupMacOS(); break;
        case 'win32': setupWindows(); break;
        case 'linux': setupLinux(); break;
        default: console.log('❌ Unsupported platform:', PLATFORM);
    }
}

console.log('');
