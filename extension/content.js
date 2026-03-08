/**
 * BrowserShield Extension v2 — Content Script
 * Scans DOM for hidden elements, trackers, ad scripts.
 * BLOCKS ad elements by removing them from the DOM.
 */

(function () {
    'use strict';

    if (window.__browsershield_scanned) return;
    window.__browsershield_scanned = true;

    if (['chrome-extension:', 'chrome:', 'edge:', 'about:', 'brave:'].includes(location.protocol)) return;

    const AD_DOMAINS = [
        'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
        'google-analytics.com', 'googletagmanager.com', 'facebook.net',
        'connect.facebook.net', 'analytics.twitter.com', 'ads.twitter.com',
        'amazon-adsystem.com', 'adsrvr.org', 'criteo.com', 'criteo.net',
        'outbrain.com', 'taboola.com', 'adnxs.com', 'rubiconproject.com',
        'pubmatic.com', 'openx.net', 'moatads.com', 'doubleverify.com',
        'quantserve.com', 'scorecardresearch.com', 'hotjar.com',
        'mouseflow.com', 'fullstory.com', 'mixpanel.com', 'amplitude.com',
        'segment.io', 'segment.com', 'optimizely.com', 'crazyegg.com',
        'chartbeat.com', 'comscore.com', 'dotomi.com', 'smartadserver.com',
        'advertising.com', 'adform.net', 'demdex.net', 'serving-sys.com',
        'mediamath.com', 'casalemedia.com', 'sharethrough.com',
        'bidswitch.net', 'indexexchange.com', 'spotxchange.com',
        'contextweb.com', 'yieldmo.com', 'stackadapt.com',
        'mathtag.com', 'bluekai.com', 'exelator.com',
        'everesttech.net', 'rlcdn.com', 'turn.com', 'nr-data.net'
    ];

    const AD_SELECTORS = [
        '[id*="google_ads"]', 'ins.adsbygoogle', '[id*="ad-container"]',
        '[class*="ad-container"]', '[class*="ad-wrapper"]', '[class*="ad-slot"]',
        '[data-ad]', '[data-ad-slot]', '[id*="sponsored"]', '[class*="sponsored"]',
        '[class*="adsbygoogle"]', '[id*="banner-ad"]', '[class*="banner-ad"]',
        '.ad-unit', '#ad-unit', '[class*="taboola"]', '[id*="taboola"]',
        '[class*="outbrain"]', '[id*="outbrain"]', '[data-native-ad]',
        'iframe[src*="doubleclick"]', 'iframe[src*="googlesyndication"]',
        'iframe[src*="facebook.com/plugins"]',
        '[class*="ad-placement"]', '[id*="dfp-ad"]'
    ];

    const results = { hiddenElements: [], trackers: [], adElements: [], totalScanned: 0, adsRemoved: 0 };

    // ===== BLOCK ADS: Remove ad containers from DOM =====
    function removeAds() {
        let removed = 0;
        AD_SELECTORS.forEach(selector => {
            try {
                document.querySelectorAll(selector).forEach(el => {
                    const rect = el.getBoundingClientRect();
                    // Only hide visible ad elements, keep reporting hidden ones
                    if (rect.width > 0 && rect.height > 0) {
                        el.style.display = 'none';
                        el.style.visibility = 'hidden';
                        el.style.height = '0';
                        el.style.overflow = 'hidden';
                        removed++;
                        results.adElements.push({
                            type: 'ad_blocked',
                            selector: el.id ? `#${el.id}` : (el.className ? `.${el.className.split(' ')[0]}` : selector),
                            size: `${Math.round(rect.width)}x${Math.round(rect.height)}`,
                            action: 'removed'
                        });
                    }
                });
            } catch { }
        });
        results.adsRemoved = removed;
    }

    // ===== Scan hidden iframes =====
    function scanHiddenIframes() {
        document.querySelectorAll('iframe').forEach(iframe => {
            const src = iframe.src || iframe.getAttribute('data-src') || '';
            const style = window.getComputedStyle(iframe);
            const rect = iframe.getBoundingClientRect();
            const isHidden = (
                style.display === 'none' || style.visibility === 'hidden' ||
                parseFloat(style.opacity) === 0 ||
                (rect.width <= 2 && rect.height <= 2) ||
                rect.width === 0 || rect.height === 0
            );

            if (isHidden && src) {
                results.hiddenElements.push({
                    type: 'hidden_iframe', url: src,
                    size: `${Math.round(rect.width)}x${Math.round(rect.height)}`,
                    reason: isHidden ? 'hidden' : 'visible'
                });
            }

            if (src && isTracker(src)) {
                // Block tracker iframes
                iframe.src = 'about:blank';
                iframe.style.display = 'none';
                results.trackers.push({
                    type: 'tracking_iframe', url: src, hidden: isHidden,
                    domain: getDomain(src), action: 'blocked'
                });
            }
        });
    }

    // ===== Scan tracking pixels =====
    function scanTrackingPixels() {
        document.querySelectorAll('img').forEach(img => {
            const src = img.src || '';
            const rect = img.getBoundingClientRect();
            const style = window.getComputedStyle(img);
            const isPixel = (
                (rect.width <= 2 && rect.height <= 2) || style.display === 'none' ||
                style.visibility === 'hidden' || parseFloat(style.opacity) === 0
            );

            if (isPixel && src.startsWith('http')) {
                results.hiddenElements.push({
                    type: 'tracking_pixel', url: src,
                    size: `${Math.round(rect.width)}x${Math.round(rect.height)}`,
                    domain: getDomain(src)
                });
            }

            if (src && isTracker(src)) {
                img.src = '';
                img.style.display = 'none';
                results.trackers.push({
                    type: 'tracking_image', url: src, hidden: isPixel,
                    domain: getDomain(src), action: 'blocked'
                });
            }
        });
    }

    // ===== Scan tracker scripts =====
    function scanTrackerScripts() {
        document.querySelectorAll('script[src]').forEach(script => {
            const src = script.src;
            if (isTracker(src)) {
                results.adElements.push({
                    type: 'ad_script', url: src, domain: getDomain(src),
                    async: script.async, defer: script.defer
                });
            }
        });
    }

    // ===== Scan beacons =====
    function scanBeacons() {
        document.querySelectorAll('link[rel="prefetch"], link[rel="preload"], link[rel="dns-prefetch"]').forEach(link => {
            if (link.href && isTracker(link.href)) {
                results.trackers.push({
                    type: 'beacon_preload', url: link.href,
                    rel: link.rel, domain: getDomain(link.href)
                });
            }
        });
    }

    // ===== Helpers =====
    function isTracker(url) {
        if (!url) return false;
        const lower = url.toLowerCase();
        return AD_DOMAINS.some(d => lower.includes(d));
    }

    function getDomain(url) {
        try { return new URL(url).hostname; } catch { return url.substring(0, 40); }
    }

    // ===== Run =====
    function runScan() {
        try {
            removeAds();
            scanHiddenIframes();
            scanTrackingPixels();
            scanTrackerScripts();
            scanBeacons();
            results.totalScanned = document.querySelectorAll('*').length;

            // De-duplicate
            const seen = new Set();
            results.trackers = results.trackers.filter(t => {
                const k = t.url || '';
                if (seen.has(k)) return false;
                seen.add(k);
                return true;
            });

            try { chrome.runtime.sendMessage({ type: 'contentScanResult', ...results }); } catch { }
        } catch (e) {
            console.debug('[BrowserShield] Scan error:', e.message);
        }
    }

    // Run scan after page settles, then again for dynamic ads
    setTimeout(runScan, 1500);
    setTimeout(runScan, 5000);

    // Watch for dynamically added ads
    const observer = new MutationObserver(() => {
        removeAds(); // Remove any newly inserted ads
    });
    observer.observe(document.body, { childList: true, subtree: true });
})();
