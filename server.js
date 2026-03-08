/**
 * BrowserShield - Main Server
 * Express HTTP server + WebSocket for real-time browser security monitoring.
 */

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const path = require('path');

const { detectInstalledBrowsers } = require('./src/core/browser-detector');
const { readHistory, readAllHistory } = require('./src/core/history-reader');
const { readBookmarks, readAllBookmarks } = require('./src/core/bookmark-reader');
const { analyzeUrl, analyzeUrls, getThreatStats } = require('./src/core/threat-analyzer');
const LiveMonitor = require('./src/core/live-monitor');
const { getInstalledApps, getRunningApps, getAppStats } = require('./src/core/app-monitor');
const { analyzeAdsInHistory } = require('./src/core/ad-tracker');
const { readAllExtensions, getExtensionStats } = require('./src/core/extension-reader');
const ProcessMonitor = require('./src/core/process-monitor');
const { getActiveConnections, getBandwidthStats, detectHiddenPackets, formatBytes } = require('./src/core/network-monitor');
const { analyzeThreat, getAIStatus, loadEnv, saveEnv } = require('./src/core/ai-agents');

const PORT = 3847;
const app = express();
const server = http.createServer(app);

// --- Detect browsers on startup ---
console.log('\n🛡️  BrowserShield — Real Browser Security Monitor');
console.log('━'.repeat(50));

let browsers = [];
try {
    browsers = detectInstalledBrowsers();
    console.log(`\n✅ Detected ${browsers.length} browser(s):`);
    for (const b of browsers) {
        console.log(`   • ${b.name} (${b.type})`);
    }
} catch (err) {
    console.error('❌ Browser detection failed:', err.message);
}

// --- Start live activity monitor ---
const liveMonitor = new LiveMonitor();
const activityFeed = []; // In-memory ring buffer for recent activity
const MAX_FEED_SIZE = 200;

liveMonitor.start(browsers);
liveMonitor.on('newActivity', (entry) => {
    const analysis = analyzeUrl(entry.url);
    const enriched = { ...entry, threat: analysis, timestamp: new Date().toISOString() };
    activityFeed.unshift(enriched);
    if (activityFeed.length > MAX_FEED_SIZE) {
        activityFeed.length = MAX_FEED_SIZE;
    }
    // Broadcast to all WebSocket clients
    broadcastWS({ type: 'newActivity', data: enriched });
});

// --- Start process monitor ---
const processMonitor = new ProcessMonitor();
processMonitor.start(3000);

processMonitor.on('browserOpened', (event) => {
    console.log(`[ProcessMonitor] 🟢 ${event.browser} opened`);
    const enriched = { ...event, eventType: 'browserOpened', timestamp: event.timestamp };
    activityFeed.unshift(enriched);
    broadcastWS({ type: 'browserEvent', data: enriched });
});

processMonitor.on('browserClosed', (event) => {
    console.log(`[ProcessMonitor] 🔴 ${event.browser} closed`);
    const enriched = { ...event, eventType: 'browserClosed', timestamp: event.timestamp };
    activityFeed.unshift(enriched);
    broadcastWS({ type: 'browserEvent', data: enriched });
});

// --- WebSocket server ---
const wss = new WebSocketServer({ server });
const wsClients = new Set();

wss.on('connection', (ws) => {
    wsClients.add(ws);
    console.log(`[WS] Client connected (${wsClients.size} total)`);

    // Send initial data to new client
    ws.send(JSON.stringify({
        type: 'init',
        data: {
            browsers: browsers.map(b => ({ id: b.id, name: b.name, icon: b.icon, type: b.type, installed: b.installed })),
            recentActivity: activityFeed.slice(0, 50)
        }
    }));

    ws.on('close', () => {
        wsClients.delete(ws);
        console.log(`[WS] Client disconnected (${wsClients.size} total)`);
    });

    ws.on('error', () => wsClients.delete(ws));
});

function broadcastWS(message) {
    const payload = JSON.stringify(message);
    for (const ws of wsClients) {
        if (ws.readyState === 1) {
            ws.send(payload);
        }
    }
}

// --- CORS for browser extension ---
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

// --- Serve static frontend ---
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// --- REST API routes ---

/**
 * GET /api/browsers
 * Returns list of detected browsers
 */
app.get('/api/browsers', (req, res) => {
    res.json({
        platform: process.platform,
        browsers: browsers.map(b => ({
            id: b.id,
            name: b.name,
            icon: b.icon,
            type: b.type,
            installed: b.installed
        }))
    });
});

/**
 * GET /api/history
 * Returns browsing history. Query params: browser, days, limit
 */
app.get('/api/history', (req, res) => {
    const { browser, days = 30, limit = 500 } = req.query;

    try {
        let history;
        if (browser) {
            const target = browsers.find(b => b.id === browser);
            if (!target) return res.status(404).json({ error: `Browser '${browser}' not found` });
            history = readHistory(target, parseInt(days), parseInt(limit));
        } else {
            history = readAllHistory(browsers, parseInt(days), parseInt(limit));
        }

        // Enrich with threat analysis
        const enriched = history.map(entry => ({
            ...entry,
            lastVisit: entry.lastVisit?.toISOString(),
            threat: analyzeUrl(entry.url)
        }));

        res.json({
            count: enriched.length,
            entries: enriched
        });
    } catch (err) {
        console.error('Error reading history:', err.message);
        res.status(500).json({ error: 'Failed to read history', details: err.message });
    }
});

/**
 * GET /api/bookmarks
 * Returns bookmarks. Query params: browser
 */
app.get('/api/bookmarks', (req, res) => {
    const { browser } = req.query;

    try {
        let bookmarks;
        if (browser) {
            const target = browsers.find(b => b.id === browser);
            if (!target) return res.status(404).json({ error: `Browser '${browser}' not found` });
            bookmarks = readBookmarks(target);
        } else {
            bookmarks = readAllBookmarks(browsers);
        }

        // Enrich with threat analysis
        const enriched = bookmarks.map(bm => ({
            ...bm,
            dateAdded: bm.dateAdded?.toISOString(),
            threat: analyzeUrl(bm.url)
        }));

        res.json({
            count: enriched.length,
            bookmarks: enriched
        });
    } catch (err) {
        console.error('Error reading bookmarks:', err.message);
        res.status(500).json({ error: 'Failed to read bookmarks', details: err.message });
    }
});

/**
 * GET /api/threats/analyze
 * Analyze a single URL. Query param: url
 */
app.get('/api/threats/analyze', (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'Missing url parameter' });

    const result = analyzeUrl(url);
    res.json(result);
});

/**
 * GET /api/stats
 * Returns aggregate statistics
 */
app.get('/api/stats', (req, res) => {
    try {
        const allHistory = readAllHistory(browsers, 7, 1000);
        const analyses = analyzeUrls(allHistory.map(h => h.url));
        const threatStats = getThreatStats(analyses);

        // Browser breakdown
        const browserBreakdown = {};
        for (const entry of allHistory) {
            browserBreakdown[entry.browser] = (browserBreakdown[entry.browser] || 0) + 1;
        }

        // Most visited domains
        const domainCounts = {};
        for (const entry of allHistory) {
            try {
                const domain = new URL(entry.url).hostname;
                domainCounts[domain] = (domainCounts[domain] || 0) + 1;
            } catch { /* skip invalid URLs */ }
        }
        const topDomains = Object.entries(domainCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15)
            .map(([domain, count]) => ({ domain, count }));

        // Hourly activity (last 24h)
        const now = new Date();
        const hourlyActivity = new Array(24).fill(0);
        for (const entry of allHistory) {
            if (entry.lastVisit) {
                const hoursAgo = Math.floor((now - entry.lastVisit) / (1000 * 60 * 60));
                if (hoursAgo >= 0 && hoursAgo < 24) {
                    hourlyActivity[23 - hoursAgo]++;
                }
            }
        }

        res.json({
            totalUrls: allHistory.length,
            browsersDetected: browsers.length,
            threats: threatStats,
            browserBreakdown,
            topDomains,
            hourlyActivity,
            liveActivityCount: activityFeed.length
        });
    } catch (err) {
        console.error('Error generating stats:', err.message);
        res.status(500).json({ error: 'Failed to generate stats', details: err.message });
    }
});

/**
 * GET /api/activity
 * Returns live activity feed
 */
app.get('/api/activity', (req, res) => {
    const { limit = 50 } = req.query;
    res.json({
        count: activityFeed.length,
        entries: activityFeed.slice(0, parseInt(limit))
    });
});

/**
 * GET /api/apps
 * Returns installed applications
 */
app.get('/api/apps', (req, res) => {
    try {
        const apps = getInstalledApps();
        const running = getRunningApps();
        const stats = getAppStats(apps);
        // Mark running apps
        const enriched = apps.map(a => ({
            ...a,
            isRunning: running.some(r => r.toLowerCase().includes(a.name.toLowerCase()))
        }));
        res.json({ apps: enriched, stats, runningCount: running.length });
    } catch (err) {
        res.status(500).json({ error: 'Failed to read apps', details: err.message });
    }
});

/**
 * GET /api/extensions
 * Returns browser extensions
 */
app.get('/api/extensions', (req, res) => {
    try {
        const extensions = readAllExtensions();
        const stats = getExtensionStats(extensions);
        res.json({ extensions, stats });
    } catch (err) {
        res.status(500).json({ error: 'Failed to read extensions', details: err.message });
    }
});

/**
 * GET /api/ads
 * Returns ad/tracker analysis from browsing history
 */
app.get('/api/ads', (req, res) => {
    try {
        const { days = 30 } = req.query;
        const allHistory = readAllHistory(browsers, parseInt(days), 2000);
        const adData = analyzeAdsInHistory(allHistory);
        res.json(adData);
    } catch (err) {
        res.status(500).json({ error: 'Failed to analyze ads', details: err.message });
    }
});

/**
 * GET /api/processes
 * Returns currently running browsers
 */
app.get('/api/processes', (req, res) => {
    const running = processMonitor.getRunningBrowsers();
    const activeWindow = processMonitor.getActiveWindowInfo();
    res.json({ running, activeWindow });
});

/**
 * GET /api/network
 * Returns network bandwidth stats, active connections, and hidden packet threats
 */
app.get('/api/network', (req, res) => {
    try {
        const bandwidth = getBandwidthStats();
        const connections = getActiveConnections();
        const threats = detectHiddenPackets();
        const suspicious = connections.filter(c => c.suspicious);
        res.json({
            bandwidth: {
                totalUpload: bandwidth.totalUpload,
                totalDownload: bandwidth.totalDownload,
                uploadFormatted: formatBytes(bandwidth.totalUpload),
                downloadFormatted: formatBytes(bandwidth.totalDownload),
                byProcess: bandwidth.byProcess
            },
            connections: connections.length,
            activeConnections: connections.slice(0, 50),
            suspiciousConnections: suspicious,
            hiddenPacketThreats: threats,
            timestamp: Date.now()
        });
    } catch (err) {
        res.status(500).json({ error: 'Network monitor error', details: err.message });
    }
});

/**
 * POST /api/ai/analyze
 * Send threat data to AI agent for analysis
 */
app.post('/api/ai/analyze', async (req, res) => {
    try {
        const result = await analyzeThreat(req.body);
        // Broadcast AI response to WebSocket clients
        broadcastWS({ type: 'ai_response', ...result, threat: req.body });
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'AI analysis failed', details: err.message });
    }
});

/**
 * GET /api/ai/status
 * Returns which AI agents are configured
 */
app.get('/api/ai/status', (req, res) => {
    res.json(getAIStatus());
});

/**
 * POST /api/ai/settings
 * Update AI provider and API keys
 */
app.post('/api/ai/settings', (req, res) => {
    try {
        saveEnv(req.body);
        res.json({ ok: true, status: getAIStatus() });
    } catch (err) {
        res.status(500).json({ error: 'Failed to save AI settings', details: err.message });
    }
});

/**
 * GET /api/url-details
 * Returns comprehensive details about a specific URL
 */
app.get('/api/url-details', (req, res) => {
    try {
        const { url } = req.query;
        if (!url) return res.status(400).json({ error: 'URL required' });

        // Get all history to find visits for this URL
        const allHistory = readAllHistory(browsers, 90, 5000);
        let domain;
        try { domain = new URL(url).hostname; } catch { domain = url; }

        // Find all visits to this domain
        const domainVisits = allHistory.filter(h => {
            try { return new URL(h.url).hostname === domain; } catch { return false; }
        });

        // Threat analysis
        const threats = analyzeUrl(url);

        // Stats
        const totalVisits = domainVisits.length;
        const uniqueUrls = [...new Set(domainVisits.map(h => h.url))].length;
        const lastVisit = domainVisits.length > 0 ?
            new Date(Math.max(...domainVisits.map(h => new Date(h.visitTime || h.lastVisit || 0).getTime()))).toISOString() : null;
        const firstVisit = domainVisits.length > 0 ?
            new Date(Math.min(...domainVisits.map(h => new Date(h.visitTime || h.lastVisit || 0).getTime()))).toISOString() : null;

        // Visit frequency by day (last 30 days)
        const visitsByDay = {};
        const now = Date.now();
        for (let i = 0; i < 30; i++) {
            const day = new Date(now - i * 86400000).toISOString().split('T')[0];
            visitsByDay[day] = 0;
        }
        for (const h of domainVisits) {
            const day = new Date(h.visitTime || h.lastVisit || 0).toISOString().split('T')[0];
            if (visitsByDay[day] !== undefined) visitsByDay[day]++;
        }

        // By browser
        const byBrowser = {};
        for (const h of domainVisits) {
            byBrowser[h.browser] = (byBrowser[h.browser] || 0) + 1;
        }

        // Recent URLs from this domain
        const recentUrls = domainVisits
            .sort((a, b) => new Date(b.visitTime || 0) - new Date(a.visitTime || 0))
            .slice(0, 20)
            .map(h => ({
                url: h.url,
                title: h.title,
                visitTime: h.visitTime || h.lastVisit,
                browser: h.browser
            }));

        // Ad/tracker check
        const adData = analyzeAdsInHistory(domainVisits);

        res.json({
            domain, url, threats,
            stats: {
                totalVisits, uniqueUrls,
                firstVisit, lastVisit,
                visitsByDay, byBrowser
            },
            recentUrls,
            adTracker: adData,
            cachedPages: uniqueUrls,
            timestamp: Date.now()
        });
    } catch (err) {
        res.status(500).json({ error: 'URL detail error', details: err.message });
    }
});

// --- Start server ---
server.listen(PORT, () => {
    console.log(`\n🚀 Server running at http://localhost:${PORT}`);
    console.log(`📡 WebSocket live on ws://localhost:${PORT}`);
    console.log('━'.repeat(50));

    // Auto-open browser
    try {
        const open = require('open');
        open(`http://localhost:${PORT}`);
    } catch {
        console.log(`\nOpen http://localhost:${PORT} in your browser`);
    }
});

// --- Graceful shutdown ---
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down BrowserShield...');
    liveMonitor.stop();
    processMonitor.stop();
    server.close();
    process.exit(0);
});

process.on('SIGTERM', () => {
    liveMonitor.stop();
    processMonitor.stop();
    server.close();
    process.exit(0);
});
