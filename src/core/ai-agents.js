/**
 * BrowserShield — AI Threat Agents
 * Integrates Gemini, OpenAI, and Claude for intelligent threat analysis.
 * Reads API keys from .env file. When a threat is detected, the active
 * AI agent analyzes it and provides recommendations or auto-blocks.
 */

const fs = require('fs');
const path = require('path');

// ===== Load .env =====
function loadEnv() {
    const envPath = path.join(__dirname, '..', '..', '.env');
    const keys = { GEMINI_API_KEY: '', OPENAI_API_KEY: '', CLAUDE_API_KEY: '', AI_PROVIDER: 'gemini' };

    try {
        if (fs.existsSync(envPath)) {
            const content = fs.readFileSync(envPath, 'utf8');
            const lines = content.split('\n');
            for (const line of lines) {
                const trimmed = line.trim();
                if (trimmed && !trimmed.startsWith('#')) {
                    const eqIdx = trimmed.indexOf('=');
                    if (eqIdx > 0) {
                        const key = trimmed.substring(0, eqIdx).trim();
                        const val = trimmed.substring(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
                        if (key in keys) keys[key] = val;
                    }
                }
            }
        }
    } catch { }

    return keys;
}

// ===== Save .env =====
function saveEnv(updates) {
    const envPath = path.join(__dirname, '..', '..', '.env');
    let content = '';

    try {
        if (fs.existsSync(envPath)) {
            content = fs.readFileSync(envPath, 'utf8');
        }
    } catch { }

    for (const [key, val] of Object.entries(updates)) {
        const regex = new RegExp(`^${key}=.*$`, 'm');
        if (regex.test(content)) {
            content = content.replace(regex, `${key}=${val}`);
        } else {
            content += `\n${key}=${val}`;
        }
    }

    fs.writeFileSync(envPath, content.trim() + '\n');
}

// ===== Gemini Analysis =====
async function analyzeWithGemini(apiKey, threatData) {
    try {
        const res = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{
                        parts: [{
                            text: `You are BrowserShield AI Security Agent. Analyze this threat and provide a concise response (max 3 sentences) with: 1) What the threat is 2) Risk level (Critical/High/Medium/Low) 3) Recommended action.

Threat Data:
${JSON.stringify(threatData, null, 2)}`
                        }]
                    }],
                    generationConfig: { maxOutputTokens: 200, temperature: 0.3 }
                }),
                signal: AbortSignal.timeout(10000)
            }
        );

        const data = await res.json();
        return {
            provider: 'gemini',
            response: data.candidates?.[0]?.content?.parts?.[0]?.text || 'Analysis unavailable',
            success: true
        };
    } catch (err) {
        return { provider: 'gemini', response: err.message, success: false };
    }
}

// ===== OpenAI Analysis =====
async function analyzeWithOpenAI(apiKey, threatData) {
    try {
        const res = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: 'You are BrowserShield AI Security Agent. Analyze threats concisely (max 3 sentences): 1) What it is 2) Risk level 3) Action to take.' },
                    { role: 'user', content: `Analyze this threat:\n${JSON.stringify(threatData, null, 2)}` }
                ],
                max_tokens: 200,
                temperature: 0.3
            }),
            signal: AbortSignal.timeout(10000)
        });

        const data = await res.json();
        return {
            provider: 'openai',
            response: data.choices?.[0]?.message?.content || 'Analysis unavailable',
            success: true
        };
    } catch (err) {
        return { provider: 'openai', response: err.message, success: false };
    }
}

// ===== Claude Analysis =====
async function analyzeWithClaude(apiKey, threatData) {
    try {
        const res = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model: 'claude-3-5-haiku-latest',
                max_tokens: 200,
                messages: [
                    { role: 'user', content: `You are BrowserShield AI Security Agent. Analyze this threat concisely (max 3 sentences): 1) What it is 2) Risk level 3) Action to take.\n\nThreat Data:\n${JSON.stringify(threatData, null, 2)}` }
                ]
            }),
            signal: AbortSignal.timeout(10000)
        });

        const data = await res.json();
        return {
            provider: 'claude',
            response: data.content?.[0]?.text || 'Analysis unavailable',
            success: true
        };
    } catch (err) {
        return { provider: 'claude', response: err.message, success: false };
    }
}

// ===== Main analyze function =====
async function analyzeThreat(threatData) {
    const env = loadEnv();
    const provider = env.AI_PROVIDER || 'gemini';

    let result;

    switch (provider) {
        case 'openai':
            if (!env.OPENAI_API_KEY) return { provider, response: 'OpenAI API key not set', success: false };
            result = await analyzeWithOpenAI(env.OPENAI_API_KEY, threatData);
            break;
        case 'claude':
            if (!env.CLAUDE_API_KEY) return { provider, response: 'Claude API key not set', success: false };
            result = await analyzeWithClaude(env.CLAUDE_API_KEY, threatData);
            break;
        case 'gemini':
        default:
            if (!env.GEMINI_API_KEY) return { provider: 'gemini', response: 'Gemini API key not set', success: false };
            result = await analyzeWithGemini(env.GEMINI_API_KEY, threatData);
            break;
    }

    return result;
}

// ===== Get AI status =====
function getAIStatus() {
    const env = loadEnv();
    return {
        provider: env.AI_PROVIDER || 'gemini',
        geminiConfigured: !!env.GEMINI_API_KEY,
        openaiConfigured: !!env.OPENAI_API_KEY,
        claudeConfigured: !!env.CLAUDE_API_KEY,
        active: !!(env.GEMINI_API_KEY || env.OPENAI_API_KEY || env.CLAUDE_API_KEY)
    };
}

module.exports = { analyzeThreat, getAIStatus, loadEnv, saveEnv };
