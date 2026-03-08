/**
 * BrowserShield — Frontend Application
 * Connects to the backend API and WebSocket for real-time security monitoring.
 */

const API = '';
let ws = null;
let activityPaused = false;
let activityCount = 0;
let allHistoryData = [];
let allBookmarksData = [];
let allAppsData = [];
let allExtensionsData = [];
let detectedBrowsers = [];

// ===== BROWSER EMOJI MAP =====
const BROWSER_EMOJI = {
    chrome: '🌐', safari: '🧭', firefox: '🦊', edge: '🔷', brave: '🦁',
    chromium: '⚙️', opera: '🔴', default: '🌍'
};

function getBrowserEmoji(icon) {
    return BROWSER_EMOJI[icon] || BROWSER_EMOJI[icon?.toLowerCase()] || BROWSER_EMOJI.default;
}

// ===== INITIALIZATION =====
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initUrlScanner();
    initWebSocket();
    loadDashboard();
    loadHistory();
    loadBookmarks();
    loadApps();
    loadExtensions();
    loadAds();
    loadNetworkStats();
    loadAIStatus();
    initAISettings();
    initUrlDetailModal();
});

// ===== NAVIGATION =====
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.dataset.section;
            if (!section) return;
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            const target = document.getElementById(`section-${section}`);
            if (target) target.classList.add('active');
            const titles = {
                dashboard: 'Dashboard', activity: 'Live Activity', history: 'Browsing History',
                bookmarks: 'Bookmarks', threats: 'Threat Analysis', apps: 'Installed Applications',
                extensions: 'Browser Extensions', ads: 'Ads & Trackers',
                network: 'Network Monitor', 'ai-settings': 'AI Security Agents'
            };
            document.getElementById('page-title').textContent = titles[section] || section;
        });
    });

    document.getElementById('menu-toggle').addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('open');
    });

    // Activity controls
    document.getElementById('activity-pause').addEventListener('click', () => {
        activityPaused = !activityPaused;
        document.getElementById('pause-icon').textContent = activityPaused ? '▶' : '⏸';
    });

    document.getElementById('activity-clear').addEventListener('click', () => {
        document.getElementById('activity-stream').innerHTML =
            '<div class="empty-state" id="activity-empty"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg><p>Stream cleared</p><span>New activity will appear here</span></div>';
        activityCount = 0;
        document.getElementById('activity-badge').textContent = '0';
    });

    // History filters
    document.getElementById('history-days').addEventListener('change', () => loadHistory());
    document.getElementById('history-search').addEventListener('input', () => filterHistory());

    // Bookmarks filter
    document.getElementById('bookmarks-search').addEventListener('input', () => filterBookmarks());

    // Threat filter
    document.getElementById('threat-filter').addEventListener('change', () => filterThreats());

    // Apps filters
    document.getElementById('apps-category-filter').addEventListener('change', () => filterApps());
    document.getElementById('apps-search').addEventListener('input', () => filterApps());

    // Extensions filter
    document.getElementById('ext-risk-filter').addEventListener('change', () => filterExtensions());
}

// ===== URL SCANNER =====
function initUrlScanner() {
    const input = document.getElementById('url-scan-input');
    const btn = document.getElementById('url-scan-btn');
    const modal = document.getElementById('scan-modal');

    btn.addEventListener('click', () => scanUrl());
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') scanUrl(); });
    document.getElementById('scan-modal-close').addEventListener('click', () => { modal.style.display = 'none'; });
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.style.display = 'none'; });
}

async function scanUrl() {
    const input = document.getElementById('url-scan-input');
    let url = input.value.trim();
    if (!url) return;
    if (!url.startsWith('http')) url = 'https://' + url;

    try {
        const res = await fetch(`${API}/api/threats/analyze?url=${encodeURIComponent(url)}`);
        const data = await res.json();
        showScanResult(data);
    } catch (err) {
        showScanResult({ url, riskScore: -1, riskLevel: 'error', threats: [{ message: 'Analysis failed' }] });
    }
}

function showScanResult(data) {
    const modal = document.getElementById('scan-modal');
    const body = document.getElementById('scan-result');
    const color = getRiskColor(data.riskLevel);

    let threatHtml = '';
    if (data.threats && data.threats.length > 0) {
        threatHtml = '<div class="scan-threats">' +
            data.threats.map(t => `<div class="scan-threat-item">⚠️ ${escapeHtml(t.message)}</div>`).join('') +
            '</div>';
    } else {
        threatHtml = '<div style="text-align:center;color:var(--green);padding:12px;">✅ No threats detected</div>';
    }

    body.innerHTML = `
    <div style="font-family:var(--mono);font-size:13px;color:var(--text-muted);word-break:break-all;margin-bottom:16px;">${escapeHtml(data.url)}</div>
    <div class="scan-result-score">
      <div class="scan-score-value" style="color:${color}">${data.riskScore >= 0 ? data.riskScore : '?'}</div>
      <div class="scan-score-label">Risk Score — <span class="risk-badge ${data.riskLevel}">${data.riskLevel.toUpperCase()}</span></div>
    </div>
    ${threatHtml}
  `;
    modal.style.display = 'flex';
}

// ===== WEBSOCKET =====
function initWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}`);

    ws.onopen = () => {
        document.getElementById('status-dot').className = 'status-dot online';
        document.getElementById('status-text').textContent = 'Monitoring Active';
        document.getElementById('live-indicator').style.opacity = '1';
    };

    ws.onclose = () => {
        document.getElementById('status-dot').className = 'status-dot offline';
        document.getElementById('status-text').textContent = 'Disconnected';
        document.getElementById('live-indicator').style.opacity = '0.3';
        setTimeout(initWebSocket, 3000);
    };

    ws.onerror = () => { };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'init') {
                detectedBrowsers = msg.data.browsers || [];
                if (msg.data.recentActivity) {
                    msg.data.recentActivity.forEach(entry => {
                        if (entry.eventType) {
                            addBrowserEventItem(entry, false);
                        } else {
                            addActivityItem(entry, false);
                        }
                    });
                }
            } else if (msg.type === 'newActivity') {
                addActivityItem(msg.data, true);
            } else if (msg.type === 'browserEvent') {
                addBrowserEventItem(msg.data, true);
            } else if (msg.type === 'ai_response') {
                handleAIResponse(msg);
            }
        } catch (e) { }
    };
}

function addActivityItem(entry, isNew) {
    if (activityPaused && isNew) return;

    const stream = document.getElementById('activity-stream');
    const empty = document.getElementById('activity-empty');
    if (empty) empty.remove();

    activityCount++;
    document.getElementById('activity-badge').textContent = activityCount > 99 ? '99+' : activityCount;

    const riskLevel = entry.threat?.riskLevel || 'safe';
    const time = entry.lastVisit ? formatTime(new Date(entry.lastVisit)) : formatTime(new Date());

    const div = document.createElement('div');
    div.className = 'activity-item';
    div.innerHTML = `
    <span class="activity-icon">${getBrowserEmoji(entry.browserIcon)}</span>
    <div class="activity-content">
      <div class="activity-title">${escapeHtml(entry.title || 'Untitled')}</div>
      <div class="activity-url">${escapeHtml(entry.url)}</div>
      <div class="activity-meta">
        <span class="activity-time">${time}</span>
        <span class="activity-browser-tag">${escapeHtml(entry.browser || '')}</span>
      </div>
    </div>
    <span class="risk-badge ${riskLevel}">${riskLevel}</span>
  `;

    if (isNew) {
        stream.prepend(div);
        while (stream.children.length > 200) stream.removeChild(stream.lastChild);
    } else {
        stream.appendChild(div);
    }
}

function addBrowserEventItem(event, isNew) {
    if (activityPaused && isNew) return;

    const stream = document.getElementById('activity-stream');
    const empty = document.getElementById('activity-empty');
    if (empty) empty.remove();

    activityCount++;
    document.getElementById('activity-badge').textContent = activityCount > 99 ? '99+' : activityCount;

    const isOpened = event.type === 'opened' || event.eventType === 'browserOpened';
    const time = formatTime(new Date(event.timestamp));

    const div = document.createElement('div');
    div.className = `activity-item browser-event ${isOpened ? '' : 'closed'}`;
    div.innerHTML = `
    <span class="activity-icon">${isOpened ? '🟢' : '🔴'}</span>
    <div class="activity-content">
      <div class="activity-title"><strong>${escapeHtml(event.browser)}</strong> ${isOpened ? 'opened' : 'closed'}</div>
      <div class="activity-meta">
        <span class="activity-time">${time}</span>
        <span class="browser-event-badge ${isOpened ? 'opened' : 'closed'}">${isOpened ? 'OPENED' : 'CLOSED'}</span>
      </div>
    </div>
  `;

    if (isNew) {
        stream.prepend(div);
        while (stream.children.length > 200) stream.removeChild(stream.lastChild);
    } else {
        stream.appendChild(div);
    }
}

// ===== DASHBOARD =====
async function loadDashboard() {
    try {
        const [browsersRes, statsRes] = await Promise.all([
            fetch(`${API}/api/browsers`),
            fetch(`${API}/api/stats`)
        ]);
        const browsersData = await browsersRes.json();
        const stats = await statsRes.json();
        detectedBrowsers = browsersData.browsers || [];

        // Stats cards
        document.getElementById('stat-browsers-count').textContent = stats.browsersDetected || 0;
        document.getElementById('stat-urls-count').textContent = formatNumber(stats.totalUrls || 0);
        document.getElementById('stat-safe-count').textContent = formatNumber(stats.threats?.safe || 0);
        const threatCount = (stats.threats?.medium || 0) + (stats.threats?.high || 0) + (stats.threats?.critical || 0);
        document.getElementById('stat-threats-count').textContent = formatNumber(threatCount);
        document.getElementById('threat-badge').textContent = threatCount;

        // Browser icons in sidebar
        const iconsEl = document.getElementById('browser-icons');
        iconsEl.innerHTML = detectedBrowsers.map(b =>
            `<span class="browser-icon-tag">${getBrowserEmoji(b.icon)} ${b.name}</span>`
        ).join('');

        // Detected browsers panel
        const browsersList = document.getElementById('detected-browsers-list');
        if (detectedBrowsers.length === 0) {
            browsersList.innerHTML = '<div class="empty-state"><p>No browsers detected</p></div>';
        } else {
            browsersList.innerHTML = detectedBrowsers.map(b => `
        <div class="browser-list-item">
          <div class="browser-list-left">
            <span class="browser-emoji">${getBrowserEmoji(b.icon)}</span>
            <div><div class="browser-list-name">${escapeHtml(b.name)}</div><div class="browser-list-type">${b.type} engine</div></div>
          </div>
          <span class="browser-list-badge">Active</span>
        </div>
      `).join('');
        }

        // Top domains
        const domainsList = document.getElementById('top-domains-list');
        const topDomains = stats.topDomains || [];
        const maxCount = topDomains.length > 0 ? topDomains[0].count : 1;
        domainsList.innerHTML = topDomains.map(d => `
      <div class="domain-item">
        <span class="domain-name">${escapeHtml(d.domain)}</span>
        <div class="domain-bar-wrap">
          <div class="domain-bar" style="width:${Math.max(4, (d.count / maxCount) * 120)}px"></div>
          <span class="domain-count">${d.count}</span>
        </div>
      </div>
    `).join('') || '<div class="empty-state"><p>No data yet</p></div>';

        // Heatmap
        const heatmap = document.getElementById('heatmap-chart');
        const hourly = stats.hourlyActivity || new Array(24).fill(0);
        const maxH = Math.max(...hourly, 1);
        heatmap.innerHTML = hourly.map((val, i) => {
            const h = Math.max(4, (val / maxH) * 100);
            const hour = ((i) % 24);
            const label = hour % 3 === 0 ? `${hour}:00` : '';
            return `<div class="heatmap-bar" style="height:${h}%" data-label="${label}"><span class="tooltip">${hour}:00 — ${val} visits</span></div>`;
        }).join('');

        // Risk breakdown
        const riskBars = document.getElementById('risk-bars');
        const t = stats.threats || {};
        const total = Math.max(t.total || 1, 1);
        riskBars.innerHTML = '';
        ['safe', 'low', 'medium', 'high', 'critical'].forEach(level => {
            const count = t[level] || 0;
            const pct = (count / total) * 100;
            riskBars.innerHTML += `
        <div class="risk-row">
          <span class="risk-label ${level}">${level}</span>
          <div class="risk-bar-track"><div class="risk-bar-fill ${level}" style="width:${pct}%"></div></div>
          <span class="risk-count">${count}</span>
        </div>
      `;
        });

        // Build browser tabs
        buildBrowserTabs();

        // Load extra stats for new features
        loadExtraDashboardStats();

    } catch (err) {
        console.error('Dashboard load error:', err);
    }
}

async function loadExtraDashboardStats() {
    try {
        const [appsRes, extRes, adsRes] = await Promise.all([
            fetch(`${API}/api/apps`),
            fetch(`${API}/api/extensions`),
            fetch(`${API}/api/ads?days=30`)
        ]);
        const appsData = await appsRes.json();
        const extData = await extRes.json();
        const adsData = await adsRes.json();

        document.getElementById('stat-apps-count').textContent = appsData.stats?.total || 0;
        document.getElementById('apps-badge').textContent = appsData.stats?.total || 0;
        document.getElementById('stat-ext-count').textContent = extData.stats?.total || 0;
        document.getElementById('ext-badge').textContent = extData.stats?.total || 0;
        document.getElementById('stat-ads-count').textContent = formatNumber(adsData.totalAds || 0);
        document.getElementById('ads-badge').textContent = adsData.totalAds || 0;
    } catch { }
}

function buildBrowserTabs() {
    const historyTabs = document.getElementById('history-browser-tabs');
    const bmTabs = document.getElementById('bookmarks-browser-tabs');

    let tabsHtml = '<span class="browser-tab active" data-browser="all">All</span>';
    detectedBrowsers.forEach(b => {
        tabsHtml += `<span class="browser-tab" data-browser="${b.id}">${getBrowserEmoji(b.icon)} ${b.name}</span>`;
    });

    historyTabs.innerHTML = tabsHtml;
    bmTabs.innerHTML = tabsHtml;

    historyTabs.querySelectorAll('.browser-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            historyTabs.querySelectorAll('.browser-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            loadHistory(tab.dataset.browser);
        });
    });

    bmTabs.querySelectorAll('.browser-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            bmTabs.querySelectorAll('.browser-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            loadBookmarks(tab.dataset.browser);
        });
    });
}

// ===== HISTORY =====
async function loadHistory(browser = 'all') {
    const days = document.getElementById('history-days').value;
    const params = new URLSearchParams({ days, limit: 500 });
    if (browser && browser !== 'all') params.set('browser', browser);

    try {
        const res = await fetch(`${API}/api/history?${params}`);
        const data = await res.json();
        allHistoryData = data.entries || [];
        renderHistory(allHistoryData);
        loadThreats(allHistoryData);
    } catch (err) {
        console.error('History load error:', err);
        document.getElementById('history-tbody').innerHTML = '<tr><td colspan="6" class="loading-cell">Failed to load history</td></tr>';
    }
}

function renderHistory(entries) {
    const tbody = document.getElementById('history-tbody');
    document.getElementById('history-count').textContent = `${entries.length} entries`;

    if (entries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">No history found</td></tr>';
        return;
    }

    tbody.innerHTML = entries.slice(0, 300).map(entry => {
        const riskLevel = entry.threat?.riskLevel || 'safe';
        const date = entry.lastVisit ? formatDate(new Date(entry.lastVisit)) : '-';
        return `<tr>
      <td>${getBrowserEmoji(entry.browserIcon)}</td>
      <td><span class="title-cell" title="${escapeHtml(entry.title)}">${escapeHtml(entry.title || 'Untitled')}</span></td>
      <td><span class="url-cell" title="${escapeHtml(entry.url)}">${escapeHtml(entry.url)}</span></td>
      <td style="text-align:center">${entry.visitCount || 1}</td>
      <td>${date}</td>
      <td><span class="risk-badge ${riskLevel}">${riskLevel}</span></td>
    </tr>`;
    }).join('');

    // Add click handlers for URL detail
    tbody.querySelectorAll('tr').forEach((row, i) => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', () => {
            const entry = entries[i];
            if (entry?.url) showUrlDetail(entry.url);
        });
    });
}

function filterHistory() {
    const q = document.getElementById('history-search').value.toLowerCase();
    if (!q) { renderHistory(allHistoryData); return; }
    const filtered = allHistoryData.filter(e =>
        (e.title || '').toLowerCase().includes(q) || (e.url || '').toLowerCase().includes(q)
    );
    renderHistory(filtered);
}

// ===== BOOKMARKS =====
async function loadBookmarks(browser = 'all') {
    const params = new URLSearchParams();
    if (browser && browser !== 'all') params.set('browser', browser);

    try {
        const res = await fetch(`${API}/api/bookmarks?${params}`);
        const data = await res.json();
        allBookmarksData = data.bookmarks || [];
        renderBookmarks(allBookmarksData);
    } catch (err) {
        console.error('Bookmarks load error:', err);
        document.getElementById('bookmarks-grid').innerHTML = '<div class="empty-state"><p>Failed to load bookmarks</p></div>';
    }
}

function renderBookmarks(bookmarks) {
    const grid = document.getElementById('bookmarks-grid');
    document.getElementById('bookmarks-count').textContent = `${bookmarks.length} bookmarks`;

    if (bookmarks.length === 0) {
        grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1;"><p>No bookmarks found</p></div>';
        return;
    }

    grid.innerHTML = bookmarks.slice(0, 200).map(bm => {
        const riskLevel = bm.threat?.riskLevel || 'safe';
        return `<div class="bookmark-card" onclick="window.open('${escapeHtml(bm.url)}','_blank')">
      <div class="bookmark-header">
        <span class="bookmark-name">${getBrowserEmoji(bm.browserIcon)} ${escapeHtml(bm.name)}</span>
        <span class="risk-badge ${riskLevel}">${riskLevel}</span>
      </div>
      <div class="bookmark-url">${escapeHtml(bm.url)}</div>
      <div class="bookmark-folder">${escapeHtml(bm.folder || 'Root')}</div>
    </div>`;
    }).join('');
}

function filterBookmarks() {
    const q = document.getElementById('bookmarks-search').value.toLowerCase();
    if (!q) { renderBookmarks(allBookmarksData); return; }
    const filtered = allBookmarksData.filter(bm =>
        (bm.name || '').toLowerCase().includes(q) || (bm.url || '').toLowerCase().includes(q) || (bm.folder || '').toLowerCase().includes(q)
    );
    renderBookmarks(filtered);
}

// ===== APPS =====
async function loadApps() {
    try {
        const res = await fetch(`${API}/api/apps`);
        const data = await res.json();
        allAppsData = data.apps || [];
        renderApps(allAppsData);
    } catch (err) {
        console.error('Apps load error:', err);
        document.getElementById('apps-grid').innerHTML = '<div class="empty-state"><p>Failed to load apps</p></div>';
    }
}

function renderApps(apps) {
    const grid = document.getElementById('apps-grid');
    document.getElementById('apps-count').textContent = `${apps.length} apps`;

    if (apps.length === 0) {
        grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1;"><p>No applications found</p></div>';
        return;
    }

    grid.innerHTML = apps.map(app => `
    <div class="app-card ${app.isRunning ? 'running' : ''}">
      <span class="app-emoji">${app.categoryEmoji || '📦'}</span>
      <div class="app-info">
        <div class="app-name" title="${escapeHtml(app.name)}">${escapeHtml(app.name)}</div>
        <div class="app-version">${escapeHtml(app.version || '')}</div>
        <span class="app-category-tag">${escapeHtml(app.category)}</span>
      </div>
      ${app.isRunning ? '<span class="app-running-dot" title="Running"></span>' : ''}
    </div>
  `).join('');
}

function filterApps() {
    const category = document.getElementById('apps-category-filter').value;
    const q = document.getElementById('apps-search').value.toLowerCase();
    let filtered = allAppsData;
    if (category !== 'all') filtered = filtered.filter(a => a.category === category);
    if (q) filtered = filtered.filter(a => a.name.toLowerCase().includes(q));
    renderApps(filtered);
}

// ===== EXTENSIONS =====
async function loadExtensions() {
    try {
        const res = await fetch(`${API}/api/extensions`);
        const data = await res.json();
        allExtensionsData = data.extensions || [];
        renderExtensions(allExtensionsData);
    } catch (err) {
        console.error('Extensions load error:', err);
        document.getElementById('extensions-grid').innerHTML = '<div class="empty-state"><p>Failed to load extensions</p></div>';
    }
}

function renderExtensions(extensions) {
    const grid = document.getElementById('extensions-grid');
    document.getElementById('ext-count').textContent = `${extensions.length} extensions`;

    if (extensions.length === 0) {
        grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1;"><p>No extensions found</p></div>';
        return;
    }

    grid.innerHTML = extensions.map(ext => {
        const permTags = (ext.permissions || []).slice(0, 8).map(p => {
            const isRisky = (ext.riskyPermissions || []).includes(p);
            return `<span class="ext-perm-tag ${isRisky ? 'risky' : ''}">${escapeHtml(p)}</span>`;
        }).join('');
        const name = ext.name?.startsWith('__MSG_') ? ext.id.slice(0, 20) : ext.name;

        return `<div class="ext-card ${ext.riskLevel}">
      <div class="ext-header">
        <span class="ext-name">${escapeHtml(name)}</span>
        <span class="risk-badge ${ext.riskLevel}">${ext.riskLevel}</span>
      </div>
      <div class="ext-browser">${getBrowserEmoji(ext.browserIcon)} ${escapeHtml(ext.browser)} · v${escapeHtml(ext.version)}</div>
      <div class="ext-perms">${permTags}</div>
      ${ext.description ? `<div class="ext-desc" title="${escapeHtml(ext.description)}">${escapeHtml(ext.description)}</div>` : ''}
    </div>`;
    }).join('');
}

function filterExtensions() {
    const level = document.getElementById('ext-risk-filter').value;
    let filtered = allExtensionsData;
    if (level !== 'all') filtered = filtered.filter(e => e.riskLevel === level);
    renderExtensions(filtered);
}

// ===== ADS & TRACKERS =====
async function loadAds() {
    try {
        const res = await fetch(`${API}/api/ads?days=30`);
        const data = await res.json();
        renderAds(data);
    } catch (err) {
        console.error('Ads load error:', err);
        document.getElementById('ads-stats').innerHTML = '<div class="empty-state"><p>Failed to load ad data</p></div>';
    }
}

function renderAds(data) {
    // Stats cards
    const statsEl = document.getElementById('ads-stats');
    statsEl.innerHTML = `
    <div class="ads-stat-card glass">
      <div class="ads-stat-value orange">${formatNumber(data.totalAds || 0)}</div>
      <div class="ads-stat-label">Total Ads / Trackers</div>
    </div>
    <div class="ads-stat-card glass">
      <div class="ads-stat-value purple">${data.adPercentage || 0}%</div>
      <div class="ads-stat-label">Of All Browsing</div>
    </div>
    <div class="ads-stat-card glass">
      <div class="ads-stat-value red">${(data.topNetworks || []).length}</div>
      <div class="ads-stat-label">Ad Networks Detected</div>
    </div>
    <div class="ads-stat-card glass">
      <div class="ads-stat-value" style="color:var(--accent)">${formatNumber(data.totalUrls || 0)}</div>
      <div class="ads-stat-label">Total URLs Analyzed</div>
    </div>
  `;

    // Top networks
    const networksEl = document.getElementById('ads-networks');
    const topNetworks = data.topNetworks || [];
    const maxNet = topNetworks.length > 0 ? topNetworks[0].count : 1;

    if (topNetworks.length > 0) {
        networksEl.innerHTML = `<h3>Top Ad Networks</h3>` +
            topNetworks.map(n => `
        <div class="ad-network-item">
          <span class="ad-network-name">${escapeHtml(n.name)}</span>
          <div class="ad-network-bar-track">
            <div class="ad-network-bar" style="width:${Math.max(2, (n.count / maxNet) * 100)}%"></div>
          </div>
          <span class="ad-network-count">${n.count}</span>
        </div>
      `).join('');
    } else {
        networksEl.innerHTML = '<div class="empty-state"><p>No ad networks detected</p><span>Your browsing appears ad-free!</span></div>';
    }

    // Recent ad entries
    const entriesEl = document.getElementById('ads-entries');
    const entries = data.entries || [];
    if (entries.length > 0) {
        entriesEl.innerHTML = '<h3>Recent Ad / Tracker URLs</h3>' +
            entries.slice(0, 50).map(e => `
        <div class="activity-item">
          <span class="activity-icon">${getBrowserEmoji(e.browserIcon)}</span>
          <div class="activity-content">
            <div class="activity-title">${escapeHtml(e.adNetwork)}</div>
            <div class="activity-url">${escapeHtml(e.url)}</div>
            <div class="activity-meta">
              <span class="activity-time">${e.lastVisit ? formatDate(new Date(e.lastVisit)) : ''}</span>
              <span class="activity-browser-tag">${escapeHtml(e.browser || '')}</span>
            </div>
          </div>
        </div>
      `).join('');
    }
}

// ===== THREATS =====
function loadThreats(historyEntries) {
    const withThreats = (historyEntries || allHistoryData).filter(e => e.threat && e.threat.riskLevel !== 'safe');
    withThreats.sort((a, b) => (b.threat?.riskScore || 0) - (a.threat?.riskScore || 0));
    renderThreats(withThreats);
}

function renderThreats(entries) {
    const list = document.getElementById('threats-list');

    if (entries.length === 0) {
        list.innerHTML = '<div class="empty-state"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg><p>No threats detected</p><span>All scanned URLs appear safe</span></div>';
        return;
    }

    list.innerHTML = entries.slice(0, 100).map(entry => {
        const t = entry.threat;
        const tagsHtml = (t.threats || []).map(th =>
            `<span class="threat-tag">${escapeHtml(th.type.replace(/_/g, ' '))}</span>`
        ).join('');

        return `<div class="threat-card ${t.riskLevel}">
      <div class="threat-header">
        <span class="threat-url">${getBrowserEmoji(entry.browserIcon)} ${escapeHtml(entry.url)}</span>
        <span class="risk-badge ${t.riskLevel}">${t.riskScore} — ${t.riskLevel.toUpperCase()}</span>
      </div>
      <div class="threat-details">${tagsHtml}</div>
      <div class="threat-meta">
        <span>${escapeHtml(entry.browser || '')}</span>
        <span>${escapeHtml(entry.title || '')}</span>
      </div>
    </div>`;
    }).join('');
}

function filterThreats() {
    const level = document.getElementById('threat-filter').value;
    let entries = allHistoryData.filter(e => e.threat && e.threat.riskLevel !== 'safe');
    if (level !== 'all') entries = entries.filter(e => e.threat.riskLevel === level);
    entries.sort((a, b) => (b.threat?.riskScore || 0) - (a.threat?.riskScore || 0));
    renderThreats(entries);
}

// ===== HELPERS =====
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatTime(date) {
    if (!date || isNaN(date)) return '';
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDate(date) {
    if (!date || isNaN(date)) return '';
    const now = new Date();
    const diff = now - date;
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return date.toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toString();
}

function getRiskColor(level) {
    const colors = { safe: '#10b981', low: '#06b6d4', medium: '#f59e0b', high: '#f97316', critical: '#ef4444' };
    return colors[level] || colors.safe;
}

// ===== NETWORK MONITOR =====
async function loadNetworkStats() {
    try {
        const res = await fetch(`${API}/api/network`);
        const data = await res.json();

        document.getElementById('net-download').textContent = data.bandwidth?.downloadFormatted || '0 B';
        document.getElementById('net-upload').textContent = data.bandwidth?.uploadFormatted || '0 B';
        document.getElementById('net-connections').textContent = data.connections || 0;
        document.getElementById('net-suspicious').textContent = data.suspiciousConnections?.length || 0;

        // Connection table
        const tbody = document.getElementById('connections-tbody');
        const conns = data.activeConnections || [];
        tbody.innerHTML = conns.slice(0, 40).map(c => `
            <tr>
                <td>${escapeHtml(c.process || '-')}</td>
                <td style="font-family:var(--mono);font-size:11px">${escapeHtml(c.remoteAddr || c.localAddr || '-')}</td>
                <td>${escapeHtml(c.state || '-')}</td>
                <td><span class="connection-status ${c.suspicious ? 'suspicious' : 'safe'}">${c.suspicious ? '⚠️ SUSPICIOUS' : '✅ Safe'}</span></td>
            </tr>
        `).join('') || '<tr><td colspan="4" class="loading-cell">No active connections</td></tr>';

        // Hidden packet threats
        const threats = data.hiddenPacketThreats || [];
        const panel = document.getElementById('hidden-threats-panel');
        const list = document.getElementById('hidden-threats-list');

        if (threats.length > 0) {
            panel.style.display = 'block';
            list.innerHTML = threats.map(t => `
                <div class="threat-alert-card">
                    <div class="threat-type">🚨 ${escapeHtml(t.type?.replace(/_/g, ' '))}</div>
                    <div class="threat-msg">${escapeHtml(t.message)}</div>
                    <div class="threat-process">Process: ${escapeHtml(t.process || '-')} | Severity: ${escapeHtml(t.severity || 'unknown')}</div>
                </div>
            `).join('');

            // Auto-trigger AI analysis for threats
            if (threats.length > 0) {
                autoAnalyzeWithAI({ type: 'hidden_packet', threats });
            }
        } else {
            panel.style.display = 'block';
            list.innerHTML = '<div style="text-align:center;padding:16px;color:var(--green)">✅ No hidden packet threats detected</div>';
        }
    } catch (err) {
        console.error('Network load error:', err);
    }
}

// Refresh network stats
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('network-refresh')?.addEventListener('click', loadNetworkStats);
    // Auto-refresh network every 15s
    setInterval(loadNetworkStats, 15000);
});

// ===== AI SETTINGS =====
async function loadAIStatus() {
    try {
        const res = await fetch(`${API}/api/ai/status`);
        const status = await res.json();

        const cards = {
            'ai-gemini': { configured: status.geminiConfigured, active: status.provider === 'gemini' },
            'ai-openai': { configured: status.openaiConfigured, active: status.provider === 'openai' },
            'ai-claude': { configured: status.claudeConfigured, active: status.provider === 'claude' }
        };

        for (const [id, info] of Object.entries(cards)) {
            const card = document.getElementById(id);
            if (!card) continue;
            card.className = 'ai-card' + (info.active && info.configured ? ' active' : info.configured ? ' configured' : '');
            card.querySelector('.ai-card-status').textContent =
                info.active && info.configured ? '✅ Active Agent' : info.configured ? '🔑 Key Set' : '❌ Not configured';
        }

        if (document.getElementById('ai-provider')) {
            document.getElementById('ai-provider').value = status.provider || 'gemini';
        }
    } catch { }
}

function initAISettings() {
    // Save button
    document.getElementById('ai-save-btn')?.addEventListener('click', async () => {
        const settings = {
            AI_PROVIDER: document.getElementById('ai-provider').value,
            GEMINI_API_KEY: document.getElementById('ai-gemini-key').value,
            OPENAI_API_KEY: document.getElementById('ai-openai-key').value,
            CLAUDE_API_KEY: document.getElementById('ai-claude-key').value
        };

        // Remove empty keys so they don't overwrite existing ones
        Object.keys(settings).forEach(k => { if (!settings[k] && k !== 'AI_PROVIDER') delete settings[k]; });

        try {
            const res = await fetch(`${API}/api/ai/settings`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            });
            const data = await res.json();
            document.getElementById('ai-save-status').textContent = '✅ Settings saved!';
            setTimeout(() => document.getElementById('ai-save-status').textContent = '', 3000);
            loadAIStatus();
        } catch (err) {
            document.getElementById('ai-save-status').textContent = '❌ Save failed';
        }
    });

    // Test button
    document.getElementById('ai-test-btn')?.addEventListener('click', async () => {
        const url = document.getElementById('ai-test-url').value.trim();
        if (!url) { alert('Enter a URL to test'); return; }

        const respEl = document.getElementById('ai-response');
        respEl.style.display = 'block';
        respEl.innerHTML = '<div style="text-align:center;padding:12px;color:var(--text-muted)">🤖 Analyzing with AI...</div>';

        try {
            const res = await fetch(`${API}/api/ai/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, type: 'manual_test' })
            });
            const data = await res.json();
            respEl.innerHTML = `
                <div class="ai-provider-badge">${escapeHtml(data.provider || 'unknown')}</div>
                <div>${escapeHtml(data.response || 'No response')}</div>
            `;
        } catch (err) {
            respEl.innerHTML = `<div style="color:var(--red)">❌ AI analysis failed: ${escapeHtml(err.message)}</div>`;
        }
    });
}

// Auto-analyze with AI when threats are detected
async function autoAnalyzeWithAI(threatData) {
    try {
        const statusRes = await fetch(`${API}/api/ai/status`);
        const status = await statusRes.json();
        if (!status.active) return; // No AI configured

        fetch(`${API}/api/ai/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(threatData)
        }).catch(() => { });
    } catch { }
}

function handleAIResponse(msg) {
    // Show AI response in activity stream as a special item
    const stream = document.getElementById('activity-stream');
    const empty = document.getElementById('activity-empty');
    if (empty) empty.remove();

    const div = document.createElement('div');
    div.className = 'activity-item browser-event';
    div.innerHTML = `
        <span class="activity-icon">🤖</span>
        <div class="activity-content">
            <div class="activity-title"><strong>AI Security Agent</strong> (${escapeHtml(msg.provider || 'AI')})</div>
            <div class="activity-url" style="color:var(--accent);white-space:normal">${escapeHtml(msg.response || '')}</div>
            <div class="activity-meta">
                <span class="activity-time">${formatTime(new Date())}</span>
                <span class="browser-event-badge opened">AI ALERT</span>
            </div>
        </div>
    `;
    stream.prepend(div);
}

// ===== URL DETAIL MODAL =====
function initUrlDetailModal() {
    const modal = document.getElementById('url-detail-modal');
    document.getElementById('url-detail-close')?.addEventListener('click', () => { modal.style.display = 'none'; });
    modal?.addEventListener('click', (e) => { if (e.target === modal) modal.style.display = 'none'; });
}

async function showUrlDetail(url) {
    const modal = document.getElementById('url-detail-modal');
    const body = document.getElementById('url-detail-body');
    body.innerHTML = '<div style="text-align:center;padding:30px;color:var(--text-muted)">Loading URL details...</div>';
    modal.style.display = 'flex';

    try {
        const res = await fetch(`${API}/api/url-details?url=${encodeURIComponent(url)}`);
        const data = await res.json();

        const score = data.threats?.riskScore || 0;
        const level = data.threats?.riskLevel || 'safe';
        const color = getRiskColor(level);

        // Visit chart
        const days = Object.entries(data.stats?.visitsByDay || {}).sort(([a], [b]) => a.localeCompare(b));
        const maxVisits = Math.max(...days.map(([, v]) => v), 1);
        const chartBars = days.map(([day, count]) => {
            const h = Math.max(2, (count / maxVisits) * 100);
            return `<div class="visit-bar" style="height:${h}%" data-count="${day.slice(5)}: ${count}" title="${day}: ${count} visits"></div>`;
        }).join('');

        // Browser breakdown
        const browserItems = Object.entries(data.stats?.byBrowser || {}).map(([b, c]) =>
            `<span style="margin-right:8px;font-size:12px">${getBrowserEmoji(b.toLowerCase())} ${escapeHtml(b)}: <strong>${c}</strong></span>`
        ).join('');

        // Recent URLs
        const recentItems = (data.recentUrls || []).slice(0, 15).map(u => `
            <div class="url-detail-recent-item">
                <span class="url-browser">${escapeHtml(u.browser || '')}</span>
                <span class="url-text" title="${escapeHtml(u.url)}">${escapeHtml(u.url)}</span>
                <span class="url-time">${u.visitTime ? formatDate(new Date(u.visitTime)) : '-'}</span>
            </div>
        `).join('');

        document.getElementById('url-detail-title').textContent = data.domain || 'URL Details';

        body.innerHTML = `
            <div class="url-detail-header">
                <div class="url-detail-score" style="border-color:${color};color:${color}">${score}</div>
                <div class="url-detail-info">
                    <div class="url-detail-domain">${escapeHtml(data.domain)}</div>
                    <div class="url-detail-url">${escapeHtml(url)}</div>
                </div>
                <span class="risk-badge ${level}" style="font-size:12px">${level.toUpperCase()}</span>
            </div>
            <div class="url-detail-stats">
                <div class="url-detail-stat"><span class="stat-val">${data.stats?.totalVisits || 0}</span><span class="stat-lbl">Total Visits</span></div>
                <div class="url-detail-stat"><span class="stat-val">${data.cachedPages || 0}</span><span class="stat-lbl">Unique Pages</span></div>
                <div class="url-detail-stat"><span class="stat-val">${data.stats?.lastVisit ? formatDate(new Date(data.stats.lastVisit)) : '-'}</span><span class="stat-lbl">Last Visit</span></div>
                <div class="url-detail-stat"><span class="stat-val">${data.stats?.firstVisit ? formatDate(new Date(data.stats.firstVisit)) : '-'}</span><span class="stat-lbl">First Visit</span></div>
            </div>
            <div class="url-detail-chart">
                <h4>📊 Visits (Last 30 Days)</h4>
                <div class="visit-bars">${chartBars}</div>
            </div>
            <div style="margin-bottom:16px">
                <h4 style="font-size:12px;color:var(--text-secondary);margin-bottom:6px">🌐 By Browser</h4>
                <div>${browserItems || '<span style="font-size:12px;color:var(--text-muted)">No browser data</span>'}</div>
            </div>
            ${(data.threats?.threats || []).length > 0 ? `
                <div style="margin-bottom:16px">
                    <h4 style="font-size:12px;color:var(--red);margin-bottom:6px">⚠️ Threats</h4>
                    ${data.threats.threats.map(t => `<div class="threat-alert-card"><div class="threat-msg">${escapeHtml(t.message)}</div></div>`).join('')}
                </div>` : ''}
            ${recentItems ? `
                <div class="url-detail-recent">
                    <h4>📋 Recent Pages on This Domain</h4>
                    ${recentItems}
                </div>` : ''}
        `;
    } catch (err) {
        body.innerHTML = `<div style="text-align:center;padding:30px;color:var(--red)">Failed to load details: ${escapeHtml(err.message)}</div>`;
    }
}
