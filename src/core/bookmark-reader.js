/**
 * BrowserShield - Bookmark Reader
 * Reads real bookmarks from all installed browsers.
 * Supports Chromium JSON, Firefox SQLite, and Safari plist formats.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

let Database;
try {
    Database = require('better-sqlite3');
} catch (e) {
    console.error('better-sqlite3 not available');
}

let plist;
try {
    plist = require('plist');
} catch (e) {
    // plist module optional, only needed for Safari on macOS
}

const TMP_DIR = path.join(os.tmpdir(), 'browsershield');

/**
 * Read bookmarks from Chromium-based browsers (Chrome, Edge, Brave)
 * The Bookmarks file is a JSON file, no SQLite needed.
 */
function readChromiumBookmarks(bookmarksPath, browserName) {
    if (!bookmarksPath || !fs.existsSync(bookmarksPath)) return [];

    try {
        const raw = fs.readFileSync(bookmarksPath, 'utf-8');
        const data = JSON.parse(raw);
        const bookmarks = [];

        function traverse(node, folderPath = '') {
            if (!node) return;

            if (node.type === 'url') {
                bookmarks.push({
                    name: node.name || 'Untitled',
                    url: node.url,
                    folder: folderPath || 'Root',
                    dateAdded: node.date_added ? chromiumBookmarkTimestamp(node.date_added) : null,
                    browser: browserName,
                    browserIcon: browserName.toLowerCase().replace(/\s+/g, '').replace('google', '').replace('microsoft', '')
                });
            } else if (node.type === 'folder' && node.children) {
                const currentFolder = folderPath ? `${folderPath} / ${node.name}` : node.name;
                for (const child of node.children) {
                    traverse(child, currentFolder);
                }
            }
        }

        // Chromium bookmarks have roots: bookmark_bar, other, synced
        if (data.roots) {
            if (data.roots.bookmark_bar) traverse(data.roots.bookmark_bar, 'Bookmarks Bar');
            if (data.roots.other) traverse(data.roots.other, 'Other Bookmarks');
            if (data.roots.synced) traverse(data.roots.synced, 'Synced Bookmarks');
        }

        return bookmarks;
    } catch (err) {
        console.error(`Error reading ${browserName} bookmarks:`, err.message);
        return [];
    }
}

/**
 * Convert Chromium bookmark timestamp (microseconds since 1601-01-01) to Date
 */
function chromiumBookmarkTimestamp(timestamp) {
    try {
        const epochDiff = 11644473600000000n;
        const ms = (BigInt(timestamp) - epochDiff) / 1000n;
        return new Date(Number(ms));
    } catch {
        return null;
    }
}

/**
 * Read bookmarks from Firefox (places.sqlite)
 */
function readFirefoxBookmarks(placesDbPath, browserName = 'Firefox') {
    if (!Database || !placesDbPath || !fs.existsSync(placesDbPath)) return [];

    const tempPath = path.join(TMP_DIR, 'firefox_bookmarks_places.sqlite');
    try {
        fs.copyFileSync(placesDbPath, tempPath);
        const walPath = placesDbPath + '-wal';
        if (fs.existsSync(walPath)) fs.copyFileSync(walPath, tempPath + '-wal');
        const shmPath = placesDbPath + '-shm';
        if (fs.existsSync(shmPath)) fs.copyFileSync(shmPath, tempPath + '-shm');
    } catch (err) {
        console.error('Failed to copy Firefox DB for bookmarks:', err.message);
        return [];
    }

    try {
        const db = new Database(tempPath, { readonly: true, fileMustExist: true });

        const query = `
      SELECT 
        b.title AS bookmark_title,
        p.url,
        p.title AS page_title,
        b.dateAdded,
        b.lastModified,
        parent.title AS folder_name
      FROM moz_bookmarks b
      JOIN moz_places p ON b.fk = p.id
      LEFT JOIN moz_bookmarks parent ON b.parent = parent.id
      WHERE b.type = 1
        AND p.url NOT LIKE 'place:%'
        AND p.url NOT LIKE 'about:%'
      ORDER BY b.dateAdded DESC
    `;

        const rows = db.prepare(query).all();
        db.close();

        return rows.map(row => ({
            name: row.bookmark_title || row.page_title || 'Untitled',
            url: row.url,
            folder: row.folder_name || 'Uncategorized',
            dateAdded: row.dateAdded ? new Date(row.dateAdded / 1000) : null,
            browser: browserName,
            browserIcon: 'firefox'
        }));
    } catch (err) {
        console.error('Error reading Firefox bookmarks:', err.message);
        return [];
    }
}

/**
 * Read bookmarks from Safari (Bookmarks.plist)
 */
function readSafariBookmarks(plistPath) {
    if (!plistPath || !fs.existsSync(plistPath)) return [];

    // Safari Bookmarks.plist can be binary plist
    // Try to read with plist module, or fall back to plutil conversion
    try {
        let data;

        if (plist) {
            const raw = fs.readFileSync(plistPath);
            // If it's a binary plist, we need plutil to convert first
            if (raw[0] === 0x62 || raw.toString('utf-8', 0, 6) === 'bplist') {
                // Binary plist - use plutil to convert to XML
                const { execSync } = require('child_process');
                const tmpXml = path.join(TMP_DIR, 'safari_bookmarks.xml');
                execSync(`plutil -convert xml1 -o "${tmpXml}" "${plistPath}"`);
                const xmlData = fs.readFileSync(tmpXml, 'utf-8');
                data = plist.parse(xmlData);
            } else {
                data = plist.parse(raw.toString('utf-8'));
            }
        } else {
            // No plist module, try plutil + JSON
            const { execSync } = require('child_process');
            const tmpJson = path.join(TMP_DIR, 'safari_bookmarks.json');
            execSync(`plutil -convert json -o "${tmpJson}" "${plistPath}"`);
            data = JSON.parse(fs.readFileSync(tmpJson, 'utf-8'));
        }

        const bookmarks = [];
        traverseSafariBookmarks(data, bookmarks, '');
        return bookmarks;
    } catch (err) {
        console.error('Error reading Safari bookmarks:', err.message);
        return [];
    }
}

/**
 * Recursively traverse Safari bookmark plist structure
 */
function traverseSafariBookmarks(node, bookmarks, folderPath) {
    if (!node) return;

    if (node.WebBookmarkType === 'WebBookmarkTypeLeaf' && node.URLString) {
        bookmarks.push({
            name: node.URIDictionary?.title || node.title || 'Untitled',
            url: node.URLString,
            folder: folderPath || 'Root',
            dateAdded: null,
            browser: 'Safari',
            browserIcon: 'safari'
        });
    } else if (node.WebBookmarkType === 'WebBookmarkTypeList' && node.Children) {
        const currentFolder = node.Title
            ? (folderPath ? `${folderPath} / ${node.Title}` : node.Title)
            : folderPath;
        for (const child of node.Children) {
            traverseSafariBookmarks(child, bookmarks, currentFolder);
        }
    }
}

/**
 * Read bookmarks from a detected browser based on its type
 */
function readBookmarks(browser) {
    if (!browser.installed || !browser.bookmarksPath) return [];

    switch (browser.type) {
        case 'chromium':
            return readChromiumBookmarks(browser.bookmarksPath, browser.name);
        case 'firefox':
            return readFirefoxBookmarks(browser.bookmarksPath, browser.name);
        case 'safari':
            return readSafariBookmarks(browser.bookmarksPath);
        default:
            return [];
    }
}

/**
 * Read bookmarks from all detected browsers
 */
function readAllBookmarks(browsers) {
    const allBookmarks = [];
    for (const browser of browsers) {
        const bookmarks = readBookmarks(browser);
        allBookmarks.push(...bookmarks);
    }
    return allBookmarks;
}

module.exports = {
    readBookmarks,
    readAllBookmarks,
    readChromiumBookmarks,
    readFirefoxBookmarks,
    readSafariBookmarks
};
