/**
 * BrowserShield — AI Threat Agents
 * Integrates Gemini, OpenAI, and Claude for intelligent threat analysis.
 * Supports model listing, key validation, and default model selection.
 */

const fs = require('fs');
const path = require('path');

const ENV_PATH = path.join(__dirname, '..', '..', '.env');

// ===== Load .env =====
function loadEnv() {
    const keys = {
        GEMINI_API_KEY: '', OPENAI_API_KEY: '', CLAUDE_API_KEY: '',
        AI_PROVIDER: 'gemini',
        GEMINI_MODEL: 'gemini-2.0-flash',
        OPENAI_MODEL: 'gpt-4o-mini',
        CLAUDE_MODEL: 'claude-3-5-haiku-latest'
    };

    try {
        if (fs.existsSync(ENV_PATH)) {
            const content = fs.readFileSync(ENV_PATH, 'utf8');
            for (const line of content.split('\n')) {
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
    let content = '';
    try { if (fs.existsSync(ENV_PATH)) content = fs.readFileSync(ENV_PATH, 'utf8'); } catch { }

    for (const [key, val] of Object.entries(updates)) {
        if (val === undefined || val === null) continue;
        const regex = new RegExp(`^${key}=.*$`, 'm');
        if (regex.test(content)) {
            content = content.replace(regex, `${key}=${val}`);
        } else {
            content += `\n${key}=${val}`;
        }
    }

    fs.writeFileSync(ENV_PATH, content.trim() + '\n');
}

// ===== Validate API Key + List Models =====

async function validateAndListGeminiModels(apiKey) {
    try {
        const res = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`,
            { signal: AbortSignal.timeout(10000) }
        );
        const data = await res.json();

        if (data.error) {
            return { valid: false, error: data.error.message || 'Invalid API key', models: [] };
        }

        const models = (data.models || [])
            .filter(m => m.supportedGenerationMethods?.includes('generateContent'))
            .map(m => ({
                id: m.name.replace('models/', ''),
                name: m.displayName || m.name,
                description: m.description || '',
                inputLimit: m.inputTokenLimit,
                outputLimit: m.outputTokenLimit
            }))
            .sort((a, b) => a.id.localeCompare(b.id));

        return { valid: true, models, error: null };
    } catch (err) {
        return { valid: false, error: err.message, models: [] };
    }
}

async function validateAndListOpenAIModels(apiKey) {
    try {
        const res = await fetch('https://api.openai.com/v1/models', {
            headers: { 'Authorization': `Bearer ${apiKey}` },
            signal: AbortSignal.timeout(10000)
        });
        const data = await res.json();

        if (data.error) {
            return { valid: false, error: data.error.message || 'Invalid API key', models: [] };
        }

        const chatModels = (data.data || [])
            .filter(m => m.id.includes('gpt') || m.id.includes('o1') || m.id.includes('o3') || m.id.includes('o4'))
            .map(m => ({
                id: m.id,
                name: m.id,
                description: `Created: ${new Date(m.created * 1000).toLocaleDateString()}`,
                owner: m.owned_by
            }))
            .sort((a, b) => a.id.localeCompare(b.id));

        return { valid: true, models: chatModels, error: null };
    } catch (err) {
        return { valid: false, error: err.message, models: [] };
    }
}

async function validateAndListClaudeModels(apiKey) {
    try {
        // Claude doesn't have a list models endpoint - provide known models
        // Validate key by sending a minimal request
        const res = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model: 'claude-3-5-haiku-latest',
                max_tokens: 10,
                messages: [{ role: 'user', content: 'Say OK' }]
            }),
            signal: AbortSignal.timeout(10000)
        });
        const data = await res.json();

        if (data.error) {
            return { valid: false, error: data.error.message || 'Invalid API key', models: [] };
        }

        // Key is valid. Return known Claude models
        const models = [
            { id: 'claude-sonnet-4-20250514', name: 'Claude Sonnet 4', description: 'Most intelligent model' },
            { id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet', description: 'Best balance of speed and intelligence' },
            { id: 'claude-3-5-haiku-latest', name: 'Claude 3.5 Haiku', description: 'Fastest, most affordable' },
            { id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', description: 'Most powerful (legacy)' },
        ];

        return { valid: true, models, error: null };
    } catch (err) {
        return { valid: false, error: err.message, models: [] };
    }
}

// ===== Analysis Functions =====

async function analyzeWithGemini(apiKey, model, threatData) {
    const res = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{
                    parts: [{
                        text: `You are BrowserShield AI Security Agent. Analyze this threat and provide a concise response (max 3 sentences) with: 1) What the threat is 2) Risk level (Critical/High/Medium/Low) 3) Recommended action.\n\nThreat Data:\n${JSON.stringify(threatData, null, 2)}`
                    }]
                }],
                generationConfig: { maxOutputTokens: 300, temperature: 0.3 }
            }),
            signal: AbortSignal.timeout(15000)
        }
    );

    const data = await res.json();

    // Check for API error
    if (data.error) {
        throw new Error(data.error.message || 'Gemini API error');
    }

    const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) {
        throw new Error('No response from Gemini. Status: ' + (data.candidates?.[0]?.finishReason || 'unknown'));
    }

    return text;
}

async function analyzeWithOpenAI(apiKey, model, threatData) {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
            model: model,
            messages: [
                { role: 'system', content: 'You are BrowserShield AI Security Agent. Analyze threats concisely (max 3 sentences): 1) What it is 2) Risk level 3) Action to take.' },
                { role: 'user', content: `Analyze this threat:\n${JSON.stringify(threatData, null, 2)}` }
            ],
            max_tokens: 300,
            temperature: 0.3
        }),
        signal: AbortSignal.timeout(15000)
    });

    const data = await res.json();

    if (data.error) {
        throw new Error(data.error.message || 'OpenAI API error');
    }

    const text = data.choices?.[0]?.message?.content;
    if (!text) {
        throw new Error('No response from OpenAI');
    }

    return text;
}

async function analyzeWithClaude(apiKey, model, threatData) {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
            model: model,
            max_tokens: 300,
            messages: [
                { role: 'user', content: `You are BrowserShield AI Security Agent. Analyze this threat concisely (max 3 sentences): 1) What it is 2) Risk level 3) Action to take.\n\nThreat Data:\n${JSON.stringify(threatData, null, 2)}` }
            ]
        }),
        signal: AbortSignal.timeout(15000)
    });

    const data = await res.json();

    if (data.error) {
        throw new Error(data.error.message || 'Claude API error');
    }

    const text = data.content?.[0]?.text;
    if (!text) {
        throw new Error('No response from Claude');
    }

    return text;
}

// ===== Main analyze function =====
async function analyzeThreat(threatData) {
    const env = loadEnv();
    const provider = env.AI_PROVIDER || 'gemini';

    let apiKey, model, analyzerFn;

    switch (provider) {
        case 'openai':
            apiKey = env.OPENAI_API_KEY;
            model = env.OPENAI_MODEL || 'gpt-4o-mini';
            analyzerFn = analyzeWithOpenAI;
            break;
        case 'claude':
            apiKey = env.CLAUDE_API_KEY;
            model = env.CLAUDE_MODEL || 'claude-3-5-haiku-latest';
            analyzerFn = analyzeWithClaude;
            break;
        case 'gemini':
        default:
            apiKey = env.GEMINI_API_KEY;
            model = env.GEMINI_MODEL || 'gemini-2.0-flash';
            analyzerFn = analyzeWithGemini;
            break;
    }

    if (!apiKey) {
        return { provider, model, response: `${provider} API key not set. Go to AI Settings to add your key.`, success: false };
    }

    try {
        const text = await analyzerFn(apiKey, model, threatData);
        return { provider, model, response: text, success: true };
    } catch (err) {
        console.error(`[AI] ${provider} error:`, err.message);
        return { provider, model, response: `Error: ${err.message}`, success: false };
    }
}

// ===== Validate key and list models =====
async function validateKey(provider, apiKey) {
    switch (provider) {
        case 'gemini': return validateAndListGeminiModels(apiKey);
        case 'openai': return validateAndListOpenAIModels(apiKey);
        case 'claude': return validateAndListClaudeModels(apiKey);
        default: return { valid: false, error: 'Unknown provider', models: [] };
    }
}

// ===== Get AI status =====
function getAIStatus() {
    const env = loadEnv();
    return {
        provider: env.AI_PROVIDER || 'gemini',
        geminiConfigured: !!env.GEMINI_API_KEY,
        openaiConfigured: !!env.OPENAI_API_KEY,
        claudeConfigured: !!env.CLAUDE_API_KEY,
        geminiModel: env.GEMINI_MODEL || 'gemini-2.0-flash',
        openaiModel: env.OPENAI_MODEL || 'gpt-4o-mini',
        claudeModel: env.CLAUDE_MODEL || 'claude-3-5-haiku-latest',
        active: !!(env.GEMINI_API_KEY || env.OPENAI_API_KEY || env.CLAUDE_API_KEY)
    };
}

module.exports = { analyzeThreat, getAIStatus, loadEnv, saveEnv, validateKey };
