/**
 * BrowserShield — Network Bandwidth Monitor
 * Tracks upload/download data usage per domain using macOS nettop or Linux netstat.
 * Also detects suspicious hidden packets / data exfiltration attempts.
 */

const { execSync } = require('child_process');
const os = require('os');
const PLATFORM = os.platform();

// ===== Known data exfiltration / suspicious domains =====
const SUSPICIOUS_DOMAINS = [
    'pastebin.com', 'hastebin.com', 'ghostbin.com', 'rentry.co',
    'discord.com/api/webhooks', 'webhook.site', 'requestbin.com',
    'pipedream.com', 'hookbin.com', 'beeceptor.com',
    'ngrok.io', 'ngrok.app', 'serveo.net', 'localhost.run',
    'tempfile.io', 'file.io', 'transfer.sh', 'anonymousfiles.io',
    'anonfiles.com', 'bayfiles.com', 'gofile.io',
    'keylogger', 'stealer', 'exfil', 'c2server', 'rat.',
    'cryptominer', 'coinhive.com', 'minergate.com'
];

// ===== Get active network connections =====
function getActiveConnections() {
    const connections = [];

    try {
        if (PLATFORM === 'darwin') {
            // Use lsof to get network connections
            const output = execSync(
                'lsof -i -n -P 2>/dev/null | grep -E "ESTABLISHED|LISTEN" | head -100',
                { encoding: 'utf8', timeout: 5000 }
            );

            const lines = output.trim().split('\n').filter(Boolean);
            for (const line of lines) {
                const parts = line.split(/\s+/);
                if (parts.length >= 9) {
                    const process = parts[0];
                    const pid = parts[1];
                    const type = parts[7]; // TCP/UDP
                    const nameField = parts[8] || '';

                    // Parse remote address
                    let localAddr = '', remoteAddr = '', state = '';
                    if (nameField.includes('->')) {
                        const [local, remote] = nameField.split('->');
                        localAddr = local;
                        remoteAddr = remote;
                        state = parts[9] || 'ESTABLISHED';
                    } else {
                        localAddr = nameField;
                        state = parts[9] || 'LISTEN';
                    }

                    connections.push({
                        process, pid: parseInt(pid), type,
                        localAddr, remoteAddr, state,
                        suspicious: isSuspicious(remoteAddr, process)
                    });
                }
            }
        } else if (PLATFORM === 'linux') {
            const output = execSync(
                'ss -tunp 2>/dev/null | head -100',
                { encoding: 'utf8', timeout: 5000 }
            );
            const lines = output.trim().split('\n').slice(1);
            for (const line of lines) {
                const parts = line.split(/\s+/);
                if (parts.length >= 5) {
                    connections.push({
                        state: parts[0], type: parts[0],
                        localAddr: parts[3], remoteAddr: parts[4],
                        process: parts[5] || 'unknown',
                        suspicious: isSuspicious(parts[4], parts[5] || '')
                    });
                }
            }
        } else if (PLATFORM === 'win32') {
            const output = execSync(
                'netstat -an -p TCP 2>nul',
                { encoding: 'utf8', timeout: 5000 }
            );
            const lines = output.trim().split('\n').slice(4);
            for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 4) {
                    connections.push({
                        type: parts[0], localAddr: parts[1],
                        remoteAddr: parts[2], state: parts[3],
                        process: 'unknown',
                        suspicious: isSuspicious(parts[2], '')
                    });
                }
            }
        }
    } catch (err) {
        // Silently fail — permissions may be needed
    }

    return connections;
}

// ===== Get bandwidth stats per process =====
function getBandwidthStats() {
    const stats = { totalUpload: 0, totalDownload: 0, byProcess: {} };

    try {
        if (PLATFORM === 'darwin') {
            // Use nettop snapshot for bandwidth
            const output = execSync(
                'nettop -P -L 1 -k time,interface,state,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_retransmit,rxbytes,txbytes,rxpackets,txpackets -t wifi -t wired -n 2>/dev/null || true',
                { encoding: 'utf8', timeout: 8000 }
            );

            // Fallback: use netstat for interface stats
            const ifOutput = execSync(
                'netstat -ib 2>/dev/null | head -20',
                { encoding: 'utf8', timeout: 5000 }
            );

            const lines = ifOutput.trim().split('\n').slice(1);
            for (const line of lines) {
                const parts = line.split(/\s+/);
                if (parts.length >= 7 && parts[0] !== 'lo0') {
                    const iface = parts[0];
                    const ibytes = parseInt(parts[6]) || 0;
                    const obytes = parseInt(parts[9]) || 0;
                    if (ibytes > 0 || obytes > 0) {
                        stats.byProcess[iface] = {
                            download: ibytes,
                            upload: obytes,
                            interface: iface
                        };
                        stats.totalDownload += ibytes;
                        stats.totalUpload += obytes;
                    }
                }
            }
        }

        // Get per-browser bandwidth estimate from lsof
        const browsers = ['chrome', 'firefox', 'safari', 'brave', 'msedge'];
        for (const browser of browsers) {
            try {
                const count = execSync(
                    `lsof -i -n -P 2>/dev/null | grep -i ${browser} | grep ESTABLISHED | wc -l`,
                    { encoding: 'utf8', timeout: 3000 }
                ).trim();
                const connCount = parseInt(count) || 0;
                if (connCount > 0) {
                    stats.byProcess[browser] = {
                        connections: connCount,
                        name: browser
                    };
                }
            } catch { }
        }
    } catch (err) {
        // Fail silently
    }

    return stats;
}

// ===== Detect hidden / suspicious packets =====
function detectHiddenPackets() {
    const threats = [];

    try {
        const connections = getActiveConnections();

        // Check for suspicious connections
        for (const conn of connections) {
            if (conn.suspicious) {
                threats.push({
                    type: 'suspicious_connection',
                    severity: 'high',
                    process: conn.process,
                    remoteAddr: conn.remoteAddr,
                    message: `Suspicious connection from ${conn.process} to ${conn.remoteAddr}`
                });
            }
        }

        // Check for unusual outbound connections on non-standard ports
        for (const conn of connections) {
            if (conn.state === 'ESTABLISHED' && conn.remoteAddr) {
                const port = parseInt(conn.remoteAddr.split(':').pop()) || 0;
                const nonStandardPorts = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321];
                if (nonStandardPorts.includes(port)) {
                    threats.push({
                        type: 'unusual_port',
                        severity: 'high',
                        process: conn.process,
                        port: port,
                        remoteAddr: conn.remoteAddr,
                        message: `Connection on suspicious port ${port} from ${conn.process}`
                    });
                }
            }
        }

        // Check for processes making too many connections (possible C2 beacon)
        const processCounts = {};
        for (const conn of connections) {
            processCounts[conn.process] = (processCounts[conn.process] || 0) + 1;
        }
        for (const [proc, count] of Object.entries(processCounts)) {
            if (count > 50 && !['Google Chrome', 'chrome', 'Safari', 'firefox', 'Brave', 'msedge'].some(b => proc.toLowerCase().includes(b.toLowerCase()))) {
                threats.push({
                    type: 'excessive_connections',
                    severity: 'medium',
                    process: proc,
                    count: count,
                    message: `${proc} has ${count} active connections (possible C2 beacon)`
                });
            }
        }
    } catch { }

    return threats;
}

function isSuspicious(addr, process) {
    if (!addr) return false;
    const lower = (addr + ' ' + process).toLowerCase();
    return SUSPICIOUS_DOMAINS.some(d => lower.includes(d));
}

// ===== Format bytes =====
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

module.exports = {
    getActiveConnections,
    getBandwidthStats,
    detectHiddenPackets,
    formatBytes
};
