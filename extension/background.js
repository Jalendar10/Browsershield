/**
 * BrowserShield Extension v2 — Background Service Worker
 * Features: URL analysis, time tracking, IP resolution, ad blocking stats, settings
 */

const SERVER = 'http://localhost:3847';

// ===== State =====
const urlCache = new Map();
const MAX_CACHE = 500;
let adsBlocked = 0;

// ===== Default Settings =====
const DEFAULT_SETTINGS = {
    adBlockEnabled: true,
    trackTime: true,
    showNotifications: true,
    customBlockList: [],
    customAllowList: []
};

// ===== Badge Colors =====
const BADGE_COLORS = {
    safe: '#10b981', low: '#06b6d4', medium: '#f59e0b',
    high: '#f97316', critical: '#ef4444', error: '#6b7280'
};

// ===== Initialize settings =====
chrome.runtime.onInstalled.addListener(async () => {
    const stored = await chrome.storage.local.get('settings');
    if (!stored.settings) {
        await chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
    }
    await chrome.storage.local.set({
        adsBlocked: 0,
        timeData: {},
        sessionStart: Date.now()
    });
    console.log('[BrowserShield] Extension installed — v2.0');
});

// ===== TIME TRACKING =====
let activeTabId = null;
let activeTabUrl = null;
let activeTabStart = Date.now();

async function recordTime() {
    if (!activeTabUrl || !activeTabStart) return;
    const elapsed = Date.now() - activeTabStart;
    if (elapsed < 1000) return; // Skip under 1 second

    let domain;
    try { domain = new URL(activeTabUrl).hostname; } catch { return; }

    const stored = await chrome.storage.local.get('timeData');
    const timeData = stored.timeData || {};

    if (!timeData[domain]) {
        timeData[domain] = { totalMs: 0, visits: 0, lastVisit: null, url: activeTabUrl };
    }
    timeData[domain].totalMs += elapsed;
    timeData[domain].visits += 1;
    timeData[domain].lastVisit = new Date().toISOString();
    timeData[domain].url = activeTabUrl;

    await chrome.storage.local.set({ timeData });
}

// Track when tab changes
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    await recordTime(); // save previous
    activeTabStart = Date.now();
    try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        activeTabId = activeInfo.tabId;
        activeTabUrl = tab.url;

        if (tab.url) {
            const analysis = await analyzeUrl(tab.url);
            updateBadge(activeInfo.tabId, analysis);
            await storeTabData(activeInfo.tabId, tab.url, tab.title, analysis);
        }
    } catch { }
});

// Track when URL changes
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        if (tabId === activeTabId && tab.url !== activeTabUrl) {
            await recordTime();
            activeTabStart = Date.now();
            activeTabUrl = tab.url;
        }
        const analysis = await analyzeUrl(tab.url);
        updateBadge(tabId, analysis);
        await storeTabData(tabId, tab.url, tab.title, analysis);
    }
});

// Save time periodically (every 30s)
setInterval(async () => {
    await recordTime();
    activeTabStart = Date.now();
}, 30000);

// ===== AD BLOCK COUNTER =====
// Count blocked requests using declarativeNetRequest
if (chrome.declarativeNetRequest?.onRuleMatchedDebug) {
    chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(async () => {
        adsBlocked++;
        const stored = await chrome.storage.local.get('adsBlocked');
        await chrome.storage.local.set({ adsBlocked: (stored.adsBlocked || 0) + 1 });
    });
}

// ===== IP RESOLUTION =====
async function resolveIP(hostname) {
    try {
        // Use DNS-over-HTTPS (Cloudflare)
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`, {
            headers: { 'Accept': 'application/dns-json' },
            signal: AbortSignal.timeout(3000)
        });
        const data = await res.json();
        if (data.Answer && data.Answer.length > 0) {
            return data.Answer.find(a => a.type === 1)?.data || null;
        }
        return null;
    } catch {
        return null;
    }
}

// ===== URL ANALYSIS =====
async function analyzeUrl(url) {
    if (!url || url.startsWith('chrome') || url.startsWith('edge') ||
        url.startsWith('about:') || url.startsWith('brave')) {
        return { riskLevel: 'safe', riskScore: 0, threats: [], url };
    }

    if (urlCache.has(url)) return urlCache.get(url);

    try {
        const res = await fetch(`${SERVER}/api/threats/analyze?url=${encodeURIComponent(url)}`, {
            signal: AbortSignal.timeout(3000)
        });
        if (!res.ok) throw new Error('API error');
        const data = await res.json();
        urlCache.set(url, data);
        if (urlCache.size > MAX_CACHE) urlCache.delete(urlCache.keys().next().value);
        return data;
    } catch {
        return localAnalyze(url);
    }
}

function localAnalyze(url) {
    let score = 0;
    const threats = [];
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'https:') { score += 15; threats.push({ type: 'no_https', message: 'Not using HTTPS' }); }
        const suspiciousTLDs = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.click', '.loan'];
        if (suspiciousTLDs.some(tld => parsed.hostname.endsWith(tld))) { score += 25; threats.push({ type: 'suspicious_tld', message: `Suspicious TLD: ${parsed.hostname}` }); }
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsed.hostname)) { score += 30; threats.push({ type: 'ip_address', message: 'IP-based URL' }); }
        if (url.length > 200) { score += 10; threats.push({ type: 'long_url', message: 'Unusually long URL' }); }
    } catch { }
    const riskLevel = score === 0 ? 'safe' : score < 20 ? 'low' : score < 40 ? 'medium' : score < 60 ? 'high' : 'critical';
    return { url, riskScore: Math.min(score, 100), riskLevel, threats };
}

// ===== BADGE =====
function updateBadge(tabId, analysis) {
    const level = analysis?.riskLevel || 'safe';
    const color = BADGE_COLORS[level] || BADGE_COLORS.safe;
    chrome.action.setBadgeBackgroundColor({ tabId, color });
    chrome.action.setBadgeText({ tabId, text: level === 'safe' ? '✓' : `${analysis.riskScore}` });
}

async function storeTabData(tabId, url, title, analysis) {
    let ip = null;
    try { ip = await resolveIP(new URL(url).hostname); } catch { }
    await chrome.storage.local.set({
        [`tab_${tabId}`]: { url, title, analysis, ip, timestamp: Date.now() }
    });
}

// ===== SETTINGS MANAGEMENT =====
async function getSettings() {
    const stored = await chrome.storage.local.get('settings');
    return stored.settings || DEFAULT_SETTINGS;
}

async function updateAdBlockRules(enabled) {
    try {
        if (enabled) {
            await chrome.declarativeNetRequest.updateEnabledRulesets({
                enableRulesetIds: ['ad_blocker_rules']
            });
        } else {
            await chrome.declarativeNetRequest.updateEnabledRulesets({
                disableRulesetIds: ['ad_blocker_rules']
            });
        }
    } catch (e) {
        console.log('[BrowserShield] Rule update error:', e.message);
    }
}

// ===== MESSAGE HANDLER =====
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'getAnalysis') {
        chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
            if (tabs[0]?.url) {
                const analysis = await analyzeUrl(tabs[0].url);
                let ip = null;
                try { ip = await resolveIP(new URL(tabs[0].url).hostname); } catch { }

                // Get time for this domain
                let timeOnSite = 0;
                try {
                    const domain = new URL(tabs[0].url).hostname;
                    const stored = await chrome.storage.local.get('timeData');
                    timeOnSite = stored.timeData?.[domain]?.totalMs || 0;
                    // Add current session
                    if (tabs[0].url === activeTabUrl) {
                        timeOnSite += Date.now() - activeTabStart;
                    }
                } catch { }

                sendResponse({
                    analysis, url: tabs[0].url, title: tabs[0].title,
                    ip, timeOnSite
                });
            } else {
                sendResponse({ analysis: { riskLevel: 'safe', riskScore: 0, threats: [] }, url: '', title: '' });
            }
        });
        return true;
    }

    if (msg.type === 'getTimeData') {
        chrome.storage.local.get('timeData').then(stored => {
            sendResponse(stored.timeData || {});
        });
        return true;
    }

    if (msg.type === 'getAdsBlocked') {
        chrome.storage.local.get('adsBlocked').then(stored => {
            sendResponse({ count: stored.adsBlocked || 0 });
        });
        return true;
    }

    if (msg.type === 'getSettings') {
        getSettings().then(s => sendResponse(s));
        return true;
    }

    if (msg.type === 'updateSettings') {
        chrome.storage.local.set({ settings: msg.settings }).then(() => {
            if (msg.settings.adBlockEnabled !== undefined) {
                updateAdBlockRules(msg.settings.adBlockEnabled);
            }
            sendResponse({ ok: true });
        });
        return true;
    }

    if (msg.type === 'getExtensions') {
        chrome.management?.getAll?.().then(exts => {
            sendResponse(exts || []);
        }).catch(() => {
            // If management API not available, try server
            fetch(`${SERVER}/api/extensions`, { signal: AbortSignal.timeout(3000) })
                .then(r => r.json())
                .then(d => sendResponse(d.extensions || []))
                .catch(() => sendResponse([]));
        });
        return true;
    }

    if (msg.type === 'contentScanResult') {
        chrome.storage.local.set({ [`scan_${sender.tab.id}`]: { ...msg, timestamp: Date.now() } });
        return true;
    }

    if (msg.type === 'getScanResult') {
        chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
            const result = await chrome.storage.local.get(`scan_${tabs[0]?.id}`);
            sendResponse(result[`scan_${tabs[0]?.id}`] || null);
        });
        return true;
    }

    if (msg.type === 'checkServer') {
        fetch(`${SERVER}/api/browsers`, { signal: AbortSignal.timeout(2000) })
            .then(r => r.ok ? sendResponse({ connected: true }) : sendResponse({ connected: false }))
            .catch(() => sendResponse({ connected: false }));
        return true;
    }
});

chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.safe });
chrome.action.setBadgeText({ text: '' });
console.log('[BrowserShield] Extension v2 loaded');
