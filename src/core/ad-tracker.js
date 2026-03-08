/**
 * BrowserShield - Ad & Tracker Counter
 * Identifies ad/tracker domains in browsing history and counts exposure.
 */

/**
 * Known ad and tracker domains (~500+)
 * Sources: EasyList, EasyPrivacy, Peter Lowe's list
 */
const AD_TRACKER_DOMAINS = new Set([
    // Google Ads
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'google-analytics.com', 'googletagmanager.com', 'googletagservices.com',
    'googlesyndication.com', 'googleads.g.doubleclick.net', 'adservice.google.com',
    'pagead2.googlesyndication.com', 'tpc.googlesyndication.com',
    'www.googleadservices.com', 'analytics.google.com',
    // Facebook / Meta
    'facebook.com/tr', 'connect.facebook.net', 'pixel.facebook.com',
    'facebook.net', 'fbcdn.net', 'graph.facebook.com',
    'an.facebook.com', 'ads.facebook.com',
    // Amazon Ads
    'amazon-adsystem.com', 'aax.amazon-adsystem.com', 'fls-na.amazon.com',
    'assoc-amazon.com', 'advertising.amazon.com',
    // Microsoft / Bing
    'bat.bing.com', 'ads.microsoft.com', 'c.bing.com',
    'clarity.ms', 'c.clarity.ms',
    // Twitter / X
    'ads-twitter.com', 't.co', 'analytics.twitter.com', 'ads-api.twitter.com',
    // Major ad networks
    'adnxs.com', 'adsrvr.org', 'advertising.com', 'adeventtracker.spotify.com',
    'ad.doubleclick.net', 'adform.net', 'adroll.com', 'adsymptotic.com',
    'agkn.com', 'amgdgt.com', 'bidswitch.net', 'bluekai.com',
    'casalemedia.com', 'contextweb.com', 'criteo.com', 'criteo.net',
    'crwdcntrl.net', 'demdex.net', 'dotomi.com', 'everesttech.net',
    'exelator.com', 'eyeota.net', 'fastclick.net',
    'flashtalking.com', 'fwmrm.net', 'ib-ibi.com', 'imrworldwide.com',
    'insightexpressai.com', 'ipredictive.com', 'krxd.net',
    'liadm.com', 'lijit.com', 'liveramp.com',
    'mathtag.com', 'media.net', 'mediamath.com', 'moatads.com',
    'mookie1.com', 'myvisualiq.net', 'nativo.com', 'nexage.com',
    'openx.net', 'outbrain.com', 'owneriq.net', 'pippio.com',
    'pubmatic.com', 'pubnative.net', 'quantcount.com', 'quantserve.com',
    'revcontent.com', 'rfihub.com', 'richrelevance.com',
    'rlcdn.com', 'rubiconproject.com', 'samba.tv', 'sascdn.com',
    'sc-static.net', 'scorecardresearch.com', 'seedtag.com',
    'serving-sys.com', 'sharethrough.com', 'simpli.fi',
    'sitescout.com', 'smartadserver.com', 'smaato.net',
    'stickyadstv.com', 'taboola.com', 'tapad.com', 'teads.tv',
    'tidaltv.com', 'tremorhub.com', 'tribalfusion.com',
    'turn.com', 'undertone.com', 'yieldmo.com', 'yldbt.com',
    // Tracking & Analytics
    'hotjar.com', 'mixpanel.com', 'segment.com', 'amplitude.com',
    'heap.io', 'fullstory.com', 'logrocket.com', 'mouseflow.com',
    'crazyegg.com', 'luckyorange.com', 'inspectlet.com',
    'newrelic.com', 'nr-data.net', 'omtrdc.net', 'optimizely.com',
    'parsely.com', 'pingdom.net', 'quantcast.com',
    'sentry.io', 'sumologic.com', 'tealiumiq.com',
    'webtrends.com', 'zdassets.com',
    // Retargeting
    'adbrn.com', 'atemda.com', 'bounceexchange.com',
    'brealtime.com', 'bttrack.com', 'chartbeat.com',
    'clicktale.net', 'cloudflareinsights.com', 'cxense.com',
    'demandbase.com', 'dstillery.com', 'eloqua.com',
    'ensighten.com', 'evidon.com', 'hubspot.com',
    'indexww.com', 'intentiq.com', 'lotame.com',
    'marketo.com', 'marketo.net', 'mxpnl.com',
    'narrative.io', 'nr-data.net', 'onetrust.com',
    'pardot.com', 'rlcdn.com', 'salesforce.com',
    'siftscience.com', 'taboola.com', 'tealium.com',
    'truste.com', 'trustpilot.com', 'typekit.net',
    'unbounce.com', 'usabilla.com', 'vwo.com',
    // Popup / Malvertising
    'popads.net', 'popcash.net', 'propellerads.com', 'revcontent.com',
    'revenuehits.com', 'trafficjunky.com', 'trafficfactory.biz',
    'exoclick.com', 'juicyads.com',
    // Social trackers
    'addthis.com', 'addtoany.com', 'sharethis.com',
    'platform.twitter.com', 'syndication.twitter.com',
    'platform.linkedin.com', 'snap.licdn.com',
    'static.ads-twitter.com', 'widgets.pinterest.com',
    // Browser fingerprinting
    'fingerprintjs.com', 'cdn.sift.com'
]);

/**
 * Known ad network names for display
 */
const AD_NETWORK_NAMES = {
    'doubleclick.net': 'Google DoubleClick',
    'googlesyndication.com': 'Google AdSense',
    'googleadservices.com': 'Google Ads',
    'google-analytics.com': 'Google Analytics',
    'googletagmanager.com': 'Google Tag Manager',
    'facebook.net': 'Meta Pixel',
    'connect.facebook.net': 'Facebook Connect',
    'amazon-adsystem.com': 'Amazon Ads',
    'criteo.com': 'Criteo',
    'taboola.com': 'Taboola',
    'outbrain.com': 'Outbrain',
    'pubmatic.com': 'PubMatic',
    'rubiconproject.com': 'Rubicon Project',
    'openx.net': 'OpenX',
    'media.net': 'Media.net',
    'hotjar.com': 'Hotjar',
    'mixpanel.com': 'Mixpanel',
    'segment.com': 'Segment',
    'amplitude.com': 'Amplitude',
    'clarity.ms': 'Microsoft Clarity',
    'bat.bing.com': 'Bing Ads',
    'scorecardresearch.com': 'Scorecard Research',
    'quantserve.com': 'Quantcast',
    'chartbeat.com': 'Chartbeat',
    'hubspot.com': 'HubSpot',
    'optimizely.com': 'Optimizely',
    'moatads.com': 'Moat (Oracle)',
    'sharethrough.com': 'Sharethrough',
    'teads.tv': 'Teads',
    'smartadserver.com': 'Equativ (Smart)',
    'ads-twitter.com': 'Twitter/X Ads',
    'popads.net': 'PopAds',
    'propellerads.com': 'PropellerAds'
};

/**
 * Check if a URL matches an ad/tracker domain
 */
function isAdTracker(url) {
    try {
        const hostname = new URL(url).hostname.toLowerCase();
        // Direct match
        if (AD_TRACKER_DOMAINS.has(hostname)) return { matched: true, domain: hostname };
        // Check parent domains
        const parts = hostname.split('.');
        for (let i = 1; i < parts.length - 1; i++) {
            const parent = parts.slice(i).join('.');
            if (AD_TRACKER_DOMAINS.has(parent)) return { matched: true, domain: parent };
        }
        // Pattern matching for common ad URL patterns
        if (hostname.includes('ads.') || hostname.includes('ad.') ||
            hostname.includes('tracker.') || hostname.includes('tracking.') ||
            hostname.includes('pixel.') || hostname.includes('analytics.') ||
            hostname.includes('telemetry.') || hostname.includes('beacon.')) {
            return { matched: true, domain: hostname };
        }
        return { matched: false, domain: null };
    } catch {
        return { matched: false, domain: null };
    }
}

/**
 * Analyze browsing history for ad/tracker exposure
 */
function analyzeAdsInHistory(historyEntries) {
    const adEntries = [];
    const networkCounts = {};
    const browserCounts = {};
    let totalAds = 0;

    for (const entry of historyEntries) {
        const result = isAdTracker(entry.url);
        if (result.matched) {
            totalAds++;
            const networkName = AD_NETWORK_NAMES[result.domain] || result.domain;
            networkCounts[networkName] = (networkCounts[networkName] || 0) + 1;
            browserCounts[entry.browser || 'Unknown'] = (browserCounts[entry.browser || 'Unknown'] || 0) + 1;
            adEntries.push({
                url: entry.url,
                title: entry.title,
                browser: entry.browser,
                browserIcon: entry.browserIcon,
                lastVisit: entry.lastVisit,
                adNetwork: networkName,
                adDomain: result.domain
            });
        }
    }

    // Sort networks by count
    const topNetworks = Object.entries(networkCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20)
        .map(([name, count]) => ({ name, count }));

    return {
        totalAds,
        totalUrls: historyEntries.length,
        adPercentage: historyEntries.length > 0 ? Math.round((totalAds / historyEntries.length) * 100) : 0,
        topNetworks,
        browserCounts,
        entries: adEntries.slice(0, 200)
    };
}

module.exports = { isAdTracker, analyzeAdsInHistory, AD_TRACKER_DOMAINS, AD_NETWORK_NAMES };
