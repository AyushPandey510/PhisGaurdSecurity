// DOM elements
const urlInput = document.getElementById('url-input');
const getCurrentUrlBtn = document.getElementById('get-current-url');
const checkUrlBtn = document.getElementById('check-url-btn');
const checkSslBtn = document.getElementById('check-ssl-btn');
const expandLinkBtn = document.getElementById('expand-link-btn');
const checkBreachBtn = document.getElementById('check-breach-btn');
const submitBreachBtn = document.getElementById('submit-breach-btn');
const breachInputs = document.getElementById('breach-inputs');
const emailInput = document.getElementById('email-input');
const passwordInput = document.getElementById('password-input');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const resultsContent = document.getElementById('results-content');
const errorDiv = document.getElementById('error');
const errorMessage = document.querySelector('.error-message');

// API base URL
const API_BASE = 'http://localhost:5000';

// Initialize popup
document.addEventListener('DOMContentLoaded', () => {
    getCurrentTabUrl();
    setupEventListeners();
});

// Get current tab URL
async function getCurrentTabUrl() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            urlInput.value = tab.url;
        }
    } catch (error) {
        console.error('Error getting current tab URL:', error);
    }
}

// Setup event listeners
function setupEventListeners() {
    getCurrentUrlBtn.addEventListener('click', getCurrentTabUrl);
    checkUrlBtn.addEventListener('click', () => performCheck('url'));
    checkSslBtn.addEventListener('click', () => performCheck('ssl'));
    expandLinkBtn.addEventListener('click', () => performCheck('link'));
    checkBreachBtn.addEventListener('click', () => {
        breachInputs.classList.toggle('hidden');
    });
    submitBreachBtn.addEventListener('click', () => performCheck('breach'));
}

// Perform security check
async function performCheck(type) {
    const url = urlInput.value.trim();
    if (!url) {
        showError('Please enter a URL');
        return;
    }

    showLoading();
    hideResults();
    hideError();

    try {
        let endpoint, data;

        switch (type) {
            case 'url':
                endpoint = '/check-url';
                data = { url };
                break;
            case 'ssl':
                endpoint = '/check-ssl';
                data = { url };
                break;
            case 'link':
                endpoint = '/expand-link';
                data = { url };
                break;
            case 'breach':
                endpoint = '/check-breach';
                data = {
                    email: emailInput.value.trim() || undefined,
                    password: passwordInput.value.trim() || undefined
                };
                if (!data.email && !data.password) {
                    showError('Please enter email or password for breach check');
                    hideLoading();
                    return;
                }
                break;
            default:
                throw new Error('Unknown check type');
        }

        const response = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        displayResults(type, result);

    } catch (error) {
        console.error('Error performing check:', error);
        showError(error.message || 'An error occurred while performing the check');
    } finally {
        hideLoading();
    }
}

// Display results
function displayResults(type, data) {
    let html = '';

    switch (type) {
        case 'url':
            const riskClass = getRiskClass(data.recommendation);
            const riskPercentage = data.risk_score;
            const riskBarWidth = riskPercentage;
            const riskBarColor = riskPercentage >= 70 ? '#e74c3c' : riskPercentage >= 40 ? '#f39c12' : '#27ae60';

            html = `
                <div class="result-item">
                    <strong>URL:</strong> ${data.url}<br>
                    <div class="risk-score-container">
                        <strong>Risk Score:</strong>
                        <div class="risk-score-bar">
                            <div class="risk-score-fill" style="width: ${riskBarWidth}%; background-color: ${riskBarColor};"></div>
                            <span class="risk-score-text">${riskPercentage}/100</span>
                        </div>
                    </div>
                    <strong>Recommendation:</strong> <span class="${riskClass}">${data.recommendation.toUpperCase()}</span><br>
                    <div class="details-section">
                        <strong>Analysis Details:</strong>
                        <ul>
                            ${data.details.map(detail => `<li>${detail}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
            break;
        case 'ssl':
            const sslDetails = data.details || {};
            const sslRiskFlags = sslDetails.risk_flags || [];
            const sslRiskScore = sslDetails.risk_score || 0;
            const sslRiskBarColor = sslRiskScore >= 70 ? '#e74c3c' : sslRiskScore >= 40 ? '#f39c12' : '#27ae60';
            const connectionType = sslDetails.connection_type || 'https';

            html = `
                <div class="result-item">
                    <strong>URL:</strong> ${data.url}<br>
                    <strong>Connection:</strong> ${connectionType.toUpperCase()}<br>
                    ${connectionType === 'https' ? `
                        <strong>SSL Valid:</strong> ${data.ssl_valid ? '✅ Yes' : '❌ No'}<br>
                        <div class="risk-score-container">
                            <strong>SSL Risk Score:</strong>
                            <div class="risk-score-bar">
                                <div class="risk-score-fill" style="width: ${sslRiskScore}%; background-color: ${sslRiskBarColor};"></div>
                                <span class="risk-score-text">${sslRiskScore}/100</span>
                            </div>
                        </div>
                        ${sslDetails.subject ? `<strong>Subject:</strong> ${sslDetails.subject.commonName || 'N/A'}<br>` : ''}
                        ${sslDetails.issuer ? `<strong>Issuer:</strong> ${sslDetails.issuer.commonName || 'N/A'}<br>` : ''}
                        ${sslDetails.days_until_expiry !== undefined ? `<strong>Days until expiry:</strong> ${sslDetails.days_until_expiry}<br>` : ''}
                        ${sslDetails.is_expired !== undefined ? `<strong>Status:</strong> ${sslDetails.is_expired ? '❌ EXPIRED' : '✅ Valid'}<br>` : ''}
                        ${sslDetails.is_wildcard !== undefined ? `<strong>Wildcard:</strong> ${sslDetails.is_wildcard ? '⚠️ Yes' : '✅ No'}<br>` : ''}
                        ${sslDetails.is_self_signed !== undefined ? `<strong>Self-signed:</strong> ${sslDetails.is_self_signed ? '🚨 Yes' : '✅ No'}<br>` : ''}
                    ` : ''}
                    ${sslRiskFlags.length > 0 ? `
                        <div class="risk-flags">
                            <strong>🔍 SSL Analysis:</strong>
                            <ul>
                                ${sslRiskFlags.map(flag => `<li>${flag}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            `;
            break;
        case 'link':
            const analysis = data.analysis || {};
            const riskFlags = analysis.risk_flags || [];
            const formattedChain = analysis.formatted_chain || `${data.original_url} → ${data.final_url}`;

            html = `
                <div class="result-item">
                    <strong>Original URL:</strong> ${data.original_url}<br>
                    <strong>Final URL:</strong> ${data.final_url}<br>
                    <strong>Redirect Count:</strong> ${data.redirect_count}<br>
                    <div class="redirect-chain">
                        <strong>Redirect Chain:</strong><br>
                        <div class="chain-display">${formattedChain}</div>
                    </div>
                    ${riskFlags.length > 0 ? `
                        <div class="risk-flags">
                            <strong>⚠️ Security Analysis:</strong>
                            <ul>
                                ${riskFlags.map(flag => `<li>${flag}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    ${analysis.suspicious ? '<div class="suspicious-warning">🚨 Suspicious redirect pattern detected!</div>' : ''}
                </div>
            `;
            break;
        case 'breach':
            html = `
                <div class="result-item">
                    ${data.password_check ? `
                        <strong>Password Breach:</strong> ${data.password_check.breached ? 'Yes' : 'No'}<br>
                        <strong>Breach Count:</strong> ${data.password_check.breach_count}<br>
                    ` : ''}
                    ${data.password_strength ? `
                        <strong>Password Strength Score:</strong> ${data.password_strength.score}/100<br>
                        <strong>Feedback:</strong> ${JSON.stringify(data.password_strength.feedback, null, 2)}<br>
                    ` : ''}
                    ${data.email_check ? `
                        <strong>Email Breach:</strong> ${data.email_check.breached ? 'Yes' : 'No'}<br>
                        <strong>Breach Count:</strong> ${data.email_check.breach_count}<br>
                    ` : ''}
                </div>
            `;
            break;
    }

    resultsContent.innerHTML = html;
    showResults();
}

// Get risk class for color coding
function getRiskClass(recommendation) {
    switch (recommendation) {
        case 'safe':
            return 'risk-safe';
        case 'caution':
            return 'risk-caution';
        case 'danger':
            return 'risk-danger';
        default:
            return '';
    }
}

// UI state management
function showLoading() {
    loading.classList.remove('hidden');
}

function hideLoading() {
    loading.classList.add('hidden');
}

function showResults() {
    results.classList.remove('hidden');
}

function hideResults() {
    results.classList.add('hidden');
}

function showError(message) {
    errorMessage.textContent = message;
    errorDiv.classList.remove('hidden');
}

function hideError() {
    errorDiv.classList.add('hidden');
}
