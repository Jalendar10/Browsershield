/**
 * BrowserShield Extension v2 — Popup Logic
 * Tabs: Security, Time, Extensions, Settings
 */

const RISK_COLORS = {
    safe: '#10b981', low: '#06b6d4', medium: '#f59e0b',
    high: '#f97316', critical: '#ef4444'
};
const RISK_LABELS = {
    safe: '✅ Safe — No threats', low: '🔵 Low Risk',
    medium: '⚠️ Medium Risk', high: '🟠 High Risk — Caution',
    critical: '🔴 Critical — Dangerous!'
};

document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    checkServerStatus();
    loadAdsBlocked();
    loadSecurityTab();
    loadScanResults();
    setupSettings();

    document.getElementById('rescan-btn')?.addEventListener('click', rescan);
});

// ===== TAB SWITCHING =====
function setupTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            const target = tab.dataset.tab;
            document.getElementById(`tab-${target}`).classList.add('active');

            // Lazy load
            if (target === 'time') loadTimeTab();
            if (target === 'extensions') loadExtensionsTab();
            if (target === 'settings') loadSettings();
        });
    });
}

// ===== SERVER STATUS =====
function checkServerStatus() {
    chrome.runtime.sendMessage({ type: 'checkServer' }, (response) => {
        const el = document.getElementById('server-status');
        const dot = document.getElementById('live-dot');
        if (response?.connected) {
            el.textContent = 'Server Connected';
            el.className = 'header-sub connected';
            dot.className = 'live-dot';
        } else {
            el.textContent = 'Offline — Local Mode';
            el.className = 'header-sub';
            dot.className = 'live-dot offline';
        }
    });
}

// ===== ADS BLOCKED =====
function loadAdsBlocked() {
    chrome.runtime.sendMessage({ type: 'getAdsBlocked' }, (response) => {
        document.getElementById('blocked-count').textContent = response?.count || 0;
    });
}

// ===== SECURITY TAB =====
function loadSecurityTab() {
    chrome.runtime.sendMessage({ type: 'getAnalysis' }, (response) => {
        if (!response) return;
        const { analysis, url, title, ip, timeOnSite } = response;
        const level = analysis?.riskLevel || 'safe';
        const score = analysis?.riskScore || 0;
        const color = RISK_COLORS[level] || RISK_COLORS.safe;

        // Score ring
        const off = 264 - (score / 100) * 264;
        const fill = document.getElementById('score-fill');
        fill.style.stroke = color;
        fill.style.strokeDashoffset = level === 'safe' ? '0' : off;
        document.getElementById('score-text').textContent = score;
        document.getElementById('score-text').style.color = color;

        // Threat level
        const lev = document.getElementById('threat-level');
        lev.textContent = RISK_LABELS[level] || level;
        lev.className = `threat-level ${level}`;

        // URL
        document.getElementById('threat-url').textContent = url || 'No URL';

        // IP
        const ipEl = document.getElementById('threat-ip');
        if (ip) {
            ipEl.textContent = `🌐 IP: ${ip}`;
        } else {
            ipEl.textContent = '';
        }

        // Time on site
        const timeEl = document.getElementById('threat-time');
        if (timeOnSite > 0) {
            timeEl.textContent = `⏱️ Time on site: ${formatTime(timeOnSite)}`;
        }

        // Threat flags
        const flags = document.getElementById('threats-list');
        const threats = analysis?.threats || [];
        flags.innerHTML = threats.map(t =>
            `<div class="threat-flag fade-in"><span>⚠️</span><span>${esc(t.message || t.type)}</span></div>`
        ).join('');
    });
}

// ===== SCAN RESULTS =====
function loadScanResults() {
    chrome.runtime.sendMessage({ type: 'getScanResult' }, (result) => {
        if (!result) {
            ['tracker-count', 'ad-count', 'hidden-count'].forEach(id =>
                document.getElementById(id).textContent = '0');
            document.getElementById('element-count').textContent = '-';
            return;
        }

        const t = result.trackers || [];
        const a = result.adElements || [];
        const h = result.hiddenElements || [];

        document.getElementById('tracker-count').textContent = t.length;
        document.getElementById('ad-count').textContent = a.length;
        document.getElementById('hidden-count').textContent = h.length;
        document.getElementById('element-count').textContent = fmtNum(result.totalScanned || 0);

        if (t.length > 0) document.getElementById('tracker-count').style.color = RISK_COLORS.high;
        if (a.length > 0) document.getElementById('ad-count').style.color = RISK_COLORS.medium;
        if (h.length > 0) document.getElementById('hidden-count').style.color = RISK_COLORS.critical;

        renderSection('hidden', h, 'type', 'url');
        renderSection('tracker', t, 'type', 'domain');
        renderSection('ad', a, 'type', 'domain');
    });
}

function renderSection(name, items, typeKey, urlKey) {
    if (items.length === 0) return;
    document.getElementById(`${name}-section`).style.display = 'block';
    document.getElementById(`${name}-badge`).textContent = items.length;
    document.getElementById(`${name}-list`).innerHTML = items.slice(0, 30).map(i =>
        `<div class="item-row fade-in">
      <span class="item-type ${name === 'tracker' ? 'tracker' : name === 'ad' ? 'ad' : ''}">${esc((i[typeKey] || '').replace(/_/g, ' '))}</span>
      <span class="item-url" title="${esc(i[urlKey] || i.url || '')}">${esc(i[urlKey] || i.url || i.selector || '-')}</span>
    </div>`
    ).join('');
}

// ===== TIME TAB =====
function loadTimeTab() {
    chrome.runtime.sendMessage({ type: 'getTimeData' }, (timeData) => {
        const list = document.getElementById('time-list');
        if (!timeData || Object.keys(timeData).length === 0) {
            list.innerHTML = '<div class="empty-msg">No time data yet. Browse some pages!</div>';
            return;
        }

        // Sort by time descending
        const entries = Object.entries(timeData)
            .sort(([, a], [, b]) => b.totalMs - a.totalMs);

        const maxMs = entries[0][1].totalMs;
        let totalMs = entries.reduce((s, [, v]) => s + v.totalMs, 0);

        document.getElementById('time-total').textContent = `Total: ${formatTime(totalMs)}`;

        list.innerHTML = entries.slice(0, 50).map(([domain, data]) => {
            const pct = Math.max(5, (data.totalMs / maxMs) * 100);
            return `
        <div class="time-item fade-in">
          <div class="time-domain">
            <div class="time-domain-name">${esc(domain)}</div>
            <div class="time-domain-visits">${data.visits} visit${data.visits !== 1 ? 's' : ''}</div>
          </div>
          <div class="time-bar-wrap">
            <div class="time-bar-track"><div class="time-bar" style="width:${pct}%"></div></div>
          </div>
          <div class="time-duration">${formatTime(data.totalMs)}</div>
        </div>`;
        }).join('');
    });
}

// ===== EXTENSIONS TAB =====
function loadExtensionsTab() {
    // Try Chrome management API first
    if (chrome.management?.getAll) {
        chrome.management.getAll((exts) => {
            renderExtensions(exts.map(e => ({
                name: e.name,
                version: e.version,
                enabled: e.enabled,
                type: e.type,
                icon: e.icons?.[e.icons.length - 1]?.url || null,
                id: e.id
            })));
        });
    } else {
        // Fallback: fetch from BrowserShield server
        chrome.runtime.sendMessage({ type: 'getExtensions' }, (exts) => {
            renderExtensions((exts || []).map(e => ({
                name: e.name || e.id,
                version: e.version || '-',
                enabled: true,
                type: 'extension',
                icon: null,
                riskLevel: e.riskLevel
            })));
        });
    }
}

function renderExtensions(exts) {
    const list = document.getElementById('ext-list');
    document.getElementById('ext-total').textContent = exts.length;

    if (exts.length === 0) {
        list.innerHTML = '<div class="empty-msg">No extensions found</div>';
        return;
    }

    list.innerHTML = exts.map(ext => `
    <div class="ext-item fade-in">
      <div class="ext-icon-wrap">
        ${ext.icon ? `<img src="${esc(ext.icon)}" alt="">` : '🧩'}
      </div>
      <div class="ext-info">
        <div class="ext-name" title="${esc(ext.name)}">${esc(ext.name)}</div>
        <div class="ext-version">v${esc(ext.version)} · ${esc(ext.type || 'extension')}</div>
      </div>
      <span class="ext-status ${ext.enabled ? 'enabled' : 'disabled'}">
        ${ext.enabled ? 'Enabled' : 'Disabled'}
      </span>
    </div>
  `).join('');
}

// ===== SETTINGS TAB =====
let currentSettings = {};

function setupSettings() {
    document.getElementById('add-block-btn').addEventListener('click', () => addUrl('block'));
    document.getElementById('add-allow-btn').addEventListener('click', () => addUrl('allow'));

    // Enter key support
    document.getElementById('block-url-input').addEventListener('keydown', e => { if (e.key === 'Enter') addUrl('block'); });
    document.getElementById('allow-url-input').addEventListener('keydown', e => { if (e.key === 'Enter') addUrl('allow'); });

    // Load settings
    loadSettings();
}

function loadSettings() {
    chrome.runtime.sendMessage({ type: 'getSettings' }, (settings) => {
        currentSettings = settings || {};
        document.getElementById('setting-adblock').checked = settings?.adBlockEnabled !== false;
        document.getElementById('setting-time').checked = settings?.trackTime !== false;
        document.getElementById('setting-notifications').checked = settings?.showNotifications !== false;

        renderUrlList('block', settings?.customBlockList || []);
        renderUrlList('allow', settings?.customAllowList || []);

        // Attach change listeners
        ['setting-adblock', 'setting-time', 'setting-notifications'].forEach(id => {
            document.getElementById(id).addEventListener('change', saveSettings);
        });
    });
}

function saveSettings() {
    currentSettings.adBlockEnabled = document.getElementById('setting-adblock').checked;
    currentSettings.trackTime = document.getElementById('setting-time').checked;
    currentSettings.showNotifications = document.getElementById('setting-notifications').checked;
    chrome.runtime.sendMessage({ type: 'updateSettings', settings: currentSettings });
}

function addUrl(type) {
    const input = document.getElementById(`${type}-url-input`);
    const domain = input.value.trim().toLowerCase();
    if (!domain) return;

    const listKey = type === 'block' ? 'customBlockList' : 'customAllowList';
    if (!currentSettings[listKey]) currentSettings[listKey] = [];
    if (!currentSettings[listKey].includes(domain)) {
        currentSettings[listKey].push(domain);
        chrome.runtime.sendMessage({ type: 'updateSettings', settings: currentSettings });
        renderUrlList(type, currentSettings[listKey]);
    }
    input.value = '';
}

function removeUrl(type, domain) {
    const listKey = type === 'block' ? 'customBlockList' : 'customAllowList';
    currentSettings[listKey] = (currentSettings[listKey] || []).filter(d => d !== domain);
    chrome.runtime.sendMessage({ type: 'updateSettings', settings: currentSettings });
    renderUrlList(type, currentSettings[listKey]);
}

function renderUrlList(type, urls) {
    const list = document.getElementById(`${type}-list`);
    if (urls.length === 0) {
        list.innerHTML = '';
        return;
    }
    list.innerHTML = urls.map(u =>
        `<span class="url-tag">${esc(u)}<span class="remove-url" data-type="${type}" data-url="${esc(u)}">×</span></span>`
    ).join('');

    list.querySelectorAll('.remove-url').forEach(btn => {
        btn.addEventListener('click', () => removeUrl(btn.dataset.type, btn.dataset.url));
    });
}

// ===== RESCAN =====
function rescan() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
            chrome.scripting.executeScript({
                target: { tabId: tabs[0].id },
                files: ['content.js']
            });
        }
    });
    setTimeout(() => {
        loadSecurityTab();
        loadScanResults();
        loadAdsBlocked();
    }, 3000);
}

// ===== SECTION TOGGLE =====
window.toggleSection = function (id) {
    const el = document.getElementById(id);
    el.classList.toggle('collapsed');
};

// ===== HELPERS =====
function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtNum(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toString();
}

function formatTime(ms) {
    const totalSec = Math.floor(ms / 1000);
    if (totalSec < 60) return `${totalSec}s`;
    const min = Math.floor(totalSec / 60);
    const sec = totalSec % 60;
    if (min < 60) return `${min}m ${sec}s`;
    const hrs = Math.floor(min / 60);
    const remMin = min % 60;
    return `${hrs}h ${remMin}m`;
}
