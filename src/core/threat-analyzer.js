/**
 * BrowserShield - Threat Analyzer
 * Analyzes URLs for security threats using heuristic scoring.
 * No external API calls - everything runs locally.
 */

/**
 * Known suspicious TLDs often used in phishing/malware
 */
const SUSPICIOUS_TLDS = new Set([
    '.xyz', '.top', '.club', '.work', '.click', '.gq', '.ml', '.cf',
    '.tk', '.ga', '.buzz', '.surf', '.monster', '.icu', '.cam',
    '.fun', '.space', '.site', '.website', '.online', '.live',
    '.rest', '.fit', '.uno', '.bid', '.loan', '.racing', '.win',
    '.download', '.stream', '.date', '.faith', '.review', '.science',
    '.party', '.trade', '.accountant', '.cricket', '.men'
]);

/**
 * Known brand domains often targeted by typosquatting
 */
const BRAND_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com',
    'paypal.com', 'netflix.com', 'instagram.com', 'twitter.com', 'linkedin.com',
    'dropbox.com', 'github.com', 'yahoo.com', 'outlook.com', 'banking.com',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
    'capitalone.com', 'usbank.com', 'americanexpress.com', 'discover.com',
    'spotify.com', 'twitch.tv', 'reddit.com', 'whatsapp.com', 'telegram.org',
    'zoom.us', 'slack.com', 'adobe.com', 'ebay.com', 'walmart.com',
    'target.com', 'bestbuy.com', 'steam.com', 'steampowered.com',
    'coinbase.com', 'binance.com', 'kraken.com'
];

/**
 * Keywords commonly found in phishing URLs
 */
const PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'secure',
    'account', 'update', 'confirm', 'bank', 'password', 'credential',
    'suspend', 'locked', 'unusual', 'activity', 'alert', 'urgent',
    'expire', 'billing', 'payment', 'wallet', 'recover', 'restore',
    'authenticate', 'validate', 'identity', 'unauthorized', 'compromised',
    'reset-password', 'security-check', 'verify-account', 'confirm-identity'
];

/**
 * Known malicious domain patterns
 */
const MALWARE_PATTERNS = [
    /free.*download/i, /crack.*software/i, /keygen/i, /warez/i,
    /torrent.*movie/i, /free.*antivirus/i, /scan.*virus/i,
    /win.*prize/i, /congratulation/i, /lottery/i, /sweepstake/i,
    /bitcoin.*double/i, /crypto.*giveaway/i, /free.*crypto/i
];

/**
 * Safe/trusted domain patterns
 */
const TRUSTED_DOMAINS = new Set([
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'x.com', 'instagram.com', 'linkedin.com', 'reddit.com',
    'github.com', 'stackoverflow.com', 'apple.com', 'microsoft.com',
    'netflix.com', 'spotify.com', 'zoom.us', 'slack.com', 'notion.so',
    'figma.com', 'vercel.com', 'netlify.com', 'cloudflare.com',
    'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
    'docs.google.com', 'drive.google.com', 'mail.google.com',
    'outlook.live.com', 'office.com', 'office365.com',
    'npmjs.com', 'pypi.org', 'crates.io', 'pkg.go.dev',
    'medium.com', 'substack.com', 'dev.to', 'hashnode.dev'
]);

/**
 * Calculate Levenshtein distance between two strings
 */
function levenshtein(a, b) {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b[i - 1] === a[j - 1]) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j] + 1
                );
            }
        }
    }
    return matrix[b.length][a.length];
}

/**
 * Analyze a URL for security threats
 * Returns a threat assessment object with risk score (0-100) and details
 */
function analyzeUrl(urlString) {
    const result = {
        url: urlString,
        riskScore: 0,
        riskLevel: 'safe',
        threats: [],
        details: {},
        timestamp: new Date().toISOString()
    };

    let parsed;
    try {
        parsed = new URL(urlString);
    } catch {
        result.riskScore = 50;
        result.riskLevel = 'medium';
        result.threats.push({ type: 'invalid_url', message: 'Unable to parse URL', severity: 50 });
        return result;
    }

    const hostname = parsed.hostname.toLowerCase();
    const fullUrl = urlString.toLowerCase();
    const pathAndQuery = (parsed.pathname + parsed.search).toLowerCase();
    let score = 0;

    // --- Check 1: HTTPS ---
    if (parsed.protocol === 'http:' && hostname !== 'localhost' && !hostname.startsWith('127.') && !hostname.startsWith('192.168.')) {
        score += 10;
        result.threats.push({ type: 'no_https', message: 'No HTTPS encryption', severity: 10 });
    }

    // --- Check 2: IP-based URL ---
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
        score += 30;
        result.threats.push({ type: 'ip_url', message: 'URL uses IP address instead of domain', severity: 30 });
    }

    // --- Check 3: Suspicious TLD ---
    const tld = '.' + hostname.split('.').pop();
    if (SUSPICIOUS_TLDS.has(tld)) {
        score += 15;
        result.threats.push({ type: 'suspicious_tld', message: `Suspicious TLD: ${tld}`, severity: 15 });
    }

    // --- Check 4: Typosquatting detection ---
    const domainParts = hostname.replace(/^www\./, '').split('.');
    const baseDomain = domainParts.slice(-2).join('.');
    for (const brand of BRAND_DOMAINS) {
        if (baseDomain === brand) break; // Exact match is fine
        const distance = levenshtein(baseDomain, brand);
        if (distance > 0 && distance <= 2) {
            score += 35;
            result.threats.push({
                type: 'typosquatting',
                message: `Possible typosquatting of ${brand} (distance: ${distance})`,
                severity: 35
            });
            break;
        }
    }

    // --- Check 5: Excessive subdomains ---
    if (domainParts.length > 4) {
        score += 15;
        result.threats.push({ type: 'excessive_subdomains', message: `Suspicious number of subdomains (${domainParts.length})`, severity: 15 });
    }

    // --- Check 6: Phishing keywords in URL ---
    let phishingCount = 0;
    for (const keyword of PHISHING_KEYWORDS) {
        if (pathAndQuery.includes(keyword) || hostname.includes(keyword)) {
            phishingCount++;
        }
    }
    if (phishingCount >= 3) {
        score += 25;
        result.threats.push({ type: 'phishing_keywords', message: `Multiple phishing keywords detected (${phishingCount})`, severity: 25 });
    } else if (phishingCount >= 1) {
        score += 5;
    }

    // --- Check 7: Malware patterns ---
    for (const pattern of MALWARE_PATTERNS) {
        if (pattern.test(fullUrl)) {
            score += 30;
            result.threats.push({ type: 'malware_pattern', message: `Matches known malware pattern: ${pattern.source}`, severity: 30 });
            break;
        }
    }

    // --- Check 8: Long URL (often used to hide true destination) ---
    if (urlString.length > 200) {
        score += 10;
        result.threats.push({ type: 'long_url', message: 'Unusually long URL', severity: 10 });
    }

    // --- Check 9: URL encoding obfuscation ---
    const encodedChars = (urlString.match(/%[0-9a-fA-F]{2}/g) || []).length;
    if (encodedChars > 5) {
        score += 15;
        result.threats.push({ type: 'obfuscated', message: `Heavy URL encoding (${encodedChars} encoded characters)`, severity: 15 });
    }

    // --- Check 10: Data/JavaScript URI ---
    if (parsed.protocol === 'data:' || parsed.protocol === 'javascript:') {
        score += 40;
        result.threats.push({ type: 'dangerous_protocol', message: `Dangerous protocol: ${parsed.protocol}`, severity: 40 });
    }

    // --- Check 11: Contains @ symbol (credential in URL) ---
    if (urlString.includes('@') && !urlString.includes('mailto:')) {
        score += 20;
        result.threats.push({ type: 'cred_in_url', message: 'URL contains @ symbol (possible credential phishing)', severity: 20 });
    }

    // --- Trusted domain bonus ---
    if (isTrustedDomain(hostname)) {
        score = Math.max(0, score - 30);
        result.details.trusted = true;
    }

    // Cap at 100
    result.riskScore = Math.min(100, score);

    // Determine risk level
    if (result.riskScore >= 70) {
        result.riskLevel = 'critical';
    } else if (result.riskScore >= 50) {
        result.riskLevel = 'high';
    } else if (result.riskScore >= 25) {
        result.riskLevel = 'medium';
    } else if (result.riskScore >= 10) {
        result.riskLevel = 'low';
    } else {
        result.riskLevel = 'safe';
    }

    return result;
}

/**
 * Check if domain is a known trusted domain
 */
function isTrustedDomain(hostname) {
    hostname = hostname.replace(/^www\./, '');
    if (TRUSTED_DOMAINS.has(hostname)) return true;

    // Check if it's a subdomain of a trusted domain
    for (const trusted of TRUSTED_DOMAINS) {
        if (hostname.endsWith('.' + trusted)) return true;
    }
    return false;
}

/**
 * Batch analyze an array of URL strings
 */
function analyzeUrls(urls) {
    return urls.map(url => analyzeUrl(typeof url === 'string' ? url : url.url));
}

/**
 * Get threat statistics from analyzed URLs
 */
function getThreatStats(analyses) {
    const stats = {
        total: analyses.length,
        safe: 0,
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
        avgRiskScore: 0,
        topThreats: {}
    };

    let totalScore = 0;
    for (const a of analyses) {
        stats[a.riskLevel]++;
        totalScore += a.riskScore;
        for (const t of a.threats) {
            stats.topThreats[t.type] = (stats.topThreats[t.type] || 0) + 1;
        }
    }

    stats.avgRiskScore = analyses.length > 0 ? Math.round(totalScore / analyses.length) : 0;
    return stats;
}

module.exports = {
    analyzeUrl,
    analyzeUrls,
    getThreatStats,
    isTrustedDomain,
    SUSPICIOUS_TLDS,
    BRAND_DOMAINS,
    PHISHING_KEYWORDS
};
