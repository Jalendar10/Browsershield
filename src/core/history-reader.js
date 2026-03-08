/**
 * BrowserShield - History Reader
 * Reads real browsing history from Chrome, Firefox, Safari, Edge, and Brave databases.
 * Copies DB files to /tmp to avoid lock conflicts with running browsers.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

let Database;
try {
    Database = require('better-sqlite3');
} catch (e) {
    console.error('better-sqlite3 not available, history reading disabled');
}

const TMP_DIR = path.join(os.tmpdir(), 'browsershield');

// Ensure tmp directory exists
if (!fs.existsSync(TMP_DIR)) {
    fs.mkdirSync(TMP_DIR, { recursive: true });
}

/**
 * Safely copy a database file to temp directory to avoid lock conflicts.
 * Also copies WAL and SHM files if they exist.
 */
function copyDbToTemp(dbPath, label) {
    const tempPath = path.join(TMP_DIR, `${label}_${path.basename(dbPath)}`);
    try {
        fs.copyFileSync(dbPath, tempPath);
        // Copy WAL file if exists
        const walPath = dbPath + '-wal';
        if (fs.existsSync(walPath)) {
            fs.copyFileSync(walPath, tempPath + '-wal');
        }
        // Copy SHM file if exists
        const shmPath = dbPath + '-shm';
        if (fs.existsSync(shmPath)) {
            fs.copyFileSync(shmPath, tempPath + '-shm');
        }
        return tempPath;
    } catch (err) {
        console.error(`Failed to copy DB ${dbPath}:`, err.message);
        return null;
    }
}

/**
 * Convert Chrome/Edge/Brave timestamp (microseconds since 1601-01-01) to Date
 */
function chromiumTimestampToDate(timestamp) {
    if (!timestamp) return null;
    // Chrome timestamp: microseconds since January 1, 1601
    const epochDiff = 11644473600000000n; // microseconds between 1601 and 1970
    const ms = (BigInt(timestamp) - epochDiff) / 1000n;
    return new Date(Number(ms));
}

/**
 * Convert Firefox timestamp (microseconds since Unix epoch) to Date
 */
function firefoxTimestampToDate(timestamp) {
    if (!timestamp) return null;
    return new Date(Math.floor(timestamp / 1000));
}

/**
 * Convert Safari timestamp (seconds since 2001-01-01) to Date
 */
function safariTimestampToDate(timestamp) {
    if (!timestamp) return null;
    // Safari/Core Data: seconds since January 1, 2001
    const coreDataEpoch = 978307200; // seconds between 1970 and 2001
    return new Date((timestamp + coreDataEpoch) * 1000);
}

/**
 * Read history from Chromium-based browsers (Chrome, Edge, Brave)
 */
function readChromiumHistory(historyPath, browserName, days = 30, limit = 500) {
    if (!Database || !historyPath) return [];

    const tempPath = copyDbToTemp(historyPath, browserName.toLowerCase().replace(/\s+/g, '_'));
    if (!tempPath) return [];

    try {
        const db = new Database(tempPath, { readonly: true, fileMustExist: true });

        // Calculate the cutoff time in Chrome's timestamp format
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);
        const cutoffChrome = (BigInt(cutoffDate.getTime()) * 1000n) + 11644473600000000n;

        const query = `
      SELECT 
        u.url,
        u.title,
        u.visit_count,
        u.last_visit_time,
        u.typed_count
      FROM urls u
      WHERE u.last_visit_time > ?
      ORDER BY u.last_visit_time DESC
      LIMIT ?
    `;

        const rows = db.prepare(query).all(cutoffChrome.toString(), limit);
        db.close();

        return rows.map(row => ({
            url: row.url,
            title: row.title || extractTitleFromUrl(row.url),
            visitCount: row.visit_count,
            lastVisit: chromiumTimestampToDate(row.last_visit_time),
            typedCount: row.typed_count || 0,
            browser: browserName,
            browserIcon: browserName.toLowerCase().replace(/\s+/g, '').replace('google', '').replace('microsoft', '')
        }));
    } catch (err) {
        console.error(`Error reading ${browserName} history:`, err.message);
        return [];
    }
}

/**
 * Read history from Firefox (places.sqlite)
 */
function readFirefoxHistory(historyPath, days = 30, limit = 500) {
    if (!Database || !historyPath) return [];

    const tempPath = copyDbToTemp(historyPath, 'firefox');
    if (!tempPath) return [];

    try {
        const db = new Database(tempPath, { readonly: true, fileMustExist: true });

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);
        const cutoffFirefox = cutoffDate.getTime() * 1000; // microseconds

        const query = `
      SELECT 
        p.url,
        p.title,
        p.visit_count,
        p.last_visit_date,
        p.frecency
      FROM moz_places p
      WHERE p.last_visit_date > ?
        AND p.url NOT LIKE 'place:%'
      ORDER BY p.last_visit_date DESC
      LIMIT ?
    `;

        const rows = db.prepare(query).all(cutoffFirefox, limit);
        db.close();

        return rows.map(row => ({
            url: row.url,
            title: row.title || extractTitleFromUrl(row.url),
            visitCount: row.visit_count,
            lastVisit: firefoxTimestampToDate(row.last_visit_date),
            frecency: row.frecency,
            browser: 'Firefox',
            browserIcon: 'firefox'
        }));
    } catch (err) {
        console.error('Error reading Firefox history:', err.message);
        return [];
    }
}

/**
 * Read history from Safari (History.db)
 */
function readSafariHistory(historyPath, days = 30, limit = 500) {
    if (!Database || !historyPath) return [];

    const tempPath = copyDbToTemp(historyPath, 'safari');
    if (!tempPath) return [];

    try {
        const db = new Database(tempPath, { readonly: true, fileMustExist: true });

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);
        const coreDataEpoch = 978307200;
        const cutoffSafari = (cutoffDate.getTime() / 1000) - coreDataEpoch;

        const query = `
      SELECT 
        hi.url,
        hv.title,
        hi.visit_count,
        hv.visit_time,
        hi.domain_expansion
      FROM history_items hi
      JOIN history_visits hv ON hi.id = hv.history_item
      WHERE hv.visit_time > ?
      ORDER BY hv.visit_time DESC
      LIMIT ?
    `;

        const rows = db.prepare(query).all(cutoffSafari, limit);
        db.close();

        return rows.map(row => ({
            url: row.url,
            title: row.title || row.domain_expansion || extractTitleFromUrl(row.url),
            visitCount: row.visit_count,
            lastVisit: safariTimestampToDate(row.visit_time),
            browser: 'Safari',
            browserIcon: 'safari'
        }));
    } catch (err) {
        console.error('Error reading Safari history:', err.message);
        return [];
    }
}

/**
 * Extract a display title from a URL when title is missing
 */
function extractTitleFromUrl(url) {
    try {
        const parsed = new URL(url);
        return parsed.hostname + (parsed.pathname !== '/' ? parsed.pathname : '');
    } catch {
        return url;
    }
}

/**
 * Read history from a detected browser based on its type
 */
function readHistory(browser, days = 30, limit = 500) {
    if (!browser.installed || !browser.historyPath) return [];

    switch (browser.type) {
        case 'chromium':
            return readChromiumHistory(browser.historyPath, browser.name, days, limit);
        case 'firefox':
            return readFirefoxHistory(browser.historyPath, days, limit);
        case 'safari':
            return readSafariHistory(browser.historyPath, days, limit);
        default:
            return [];
    }
}

/**
 * Read history from all detected browsers
 */
function readAllHistory(browsers, days = 30, limit = 500) {
    const allHistory = [];
    for (const browser of browsers) {
        const history = readHistory(browser, days, limit);
        allHistory.push(...history);
    }
    // Sort by lastVisit descending
    allHistory.sort((a, b) => (b.lastVisit?.getTime() || 0) - (a.lastVisit?.getTime() || 0));
    return allHistory;
}

/**
 * Get the most recent history entries (used by live monitor for diffing)
 */
function getRecentEntries(browser, minutes = 5) {
    if (!browser.installed || !browser.historyPath) return [];

    const tempPath = copyDbToTemp(browser.historyPath, browser.id + '_recent');
    if (!tempPath || !Database) return [];

    try {
        const db = new Database(tempPath, { readonly: true, fileMustExist: true });
        let rows = [];

        if (browser.type === 'chromium') {
            const cutoff = new Date();
            cutoff.setMinutes(cutoff.getMinutes() - minutes);
            const cutoffChrome = (BigInt(cutoff.getTime()) * 1000n) + 11644473600000000n;
            rows = db.prepare(`
        SELECT url, title, visit_count, last_visit_time 
        FROM urls WHERE last_visit_time > ? 
        ORDER BY last_visit_time DESC LIMIT 20
      `).all(cutoffChrome.toString());

            rows = rows.map(r => ({
                url: r.url,
                title: r.title || extractTitleFromUrl(r.url),
                visitCount: r.visit_count,
                lastVisit: chromiumTimestampToDate(r.last_visit_time),
                browser: browser.name,
                browserIcon: browser.icon
            }));
        } else if (browser.type === 'firefox') {
            const cutoff = new Date();
            cutoff.setMinutes(cutoff.getMinutes() - minutes);
            const cutoffFF = cutoff.getTime() * 1000;
            rows = db.prepare(`
        SELECT url, title, visit_count, last_visit_date 
        FROM moz_places WHERE last_visit_date > ? AND url NOT LIKE 'place:%'
        ORDER BY last_visit_date DESC LIMIT 20
      `).all(cutoffFF);

            rows = rows.map(r => ({
                url: r.url,
                title: r.title || extractTitleFromUrl(r.url),
                visitCount: r.visit_count,
                lastVisit: firefoxTimestampToDate(r.last_visit_date),
                browser: 'Firefox',
                browserIcon: 'firefox'
            }));
        } else if (browser.type === 'safari') {
            const cutoff = new Date();
            cutoff.setMinutes(cutoff.getMinutes() - minutes);
            const coreDataEpoch = 978307200;
            const cutoffSafari = (cutoff.getTime() / 1000) - coreDataEpoch;
            rows = db.prepare(`
        SELECT hi.url, hv.title, hi.visit_count, hv.visit_time
        FROM history_items hi JOIN history_visits hv ON hi.id = hv.history_item
        WHERE hv.visit_time > ? ORDER BY hv.visit_time DESC LIMIT 20
      `).all(cutoffSafari);

            rows = rows.map(r => ({
                url: r.url,
                title: r.title || extractTitleFromUrl(r.url),
                visitCount: r.visit_count,
                lastVisit: safariTimestampToDate(r.visit_time),
                browser: 'Safari',
                browserIcon: 'safari'
            }));
        }

        db.close();
        return rows;
    } catch (err) {
        return [];
    }
}

module.exports = {
    readHistory,
    readAllHistory,
    readChromiumHistory,
    readFirefoxHistory,
    readSafariHistory,
    getRecentEntries,
    chromiumTimestampToDate,
    firefoxTimestampToDate,
    safariTimestampToDate
};
