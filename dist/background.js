// PhisGuard Background Service Worker
// Handles API communication, caching, and offline functionality

console.log('PhisGuard: Background service worker starting...');

const API_BASE_URL = 'http://localhost:5000';
const CACHE_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second

// Request queue for offline handling
let requestQueue = [];

// Auto-check settings
let autoCheckEnabled = true;
let notificationThreshold = 40; // Only notify for medium+ risk
let lastCheckedUrls = new Set(); // Prevent duplicate checks
let lastCheckTime = 0; // Throttle checks
const CHECK_THROTTLE_MS = 2000; // Minimum 2 seconds between checks

// Logging utility
function log(level, message, data = null) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level,
    message,
    data
  };

  console.log(`[${level.toUpperCase()}] ${timestamp}: ${message}`, data || '');

  // Store logs in chrome.storage for debugging
  chrome.storage.local.get(['logs'], (result) => {
    const logs = result.logs || [];
    logs.push(logEntry);
    // Keep only last 100 logs
    if (logs.length > 100) {
      logs.shift();
    }
    chrome.storage.local.set({ logs });
  });
}

// Initialize service worker
chrome.runtime.onInstalled.addListener((details) => {
  log('info', 'PhisGuard extension installed/updated', {
    reason: details.reason,
    version: chrome.runtime.getManifest().version
  });

  // Initialize storage structure
  chrome.storage.local.set({
    cache: {},
    settings: {
      offlineMode: false,
      cacheEnabled: true,
      autoCheckEnabled: true,
      notificationThreshold: 40
    },
    logs: []
  });

  // Clear old cache entries on update
  if (details.reason === 'update') {
    clearExpiredCache();
  }

  // Initialize auto-check for new installations
  initializeAutoCheck();
});

// Handle extension startup
chrome.runtime.onStartup.addListener(() => {
  log('info', 'PhisGuard service worker started');
  processQueuedRequests();
  initializeAutoCheck();
});

// Initialize auto-check functionality
function initializeAutoCheck() {
  // Load settings from storage
  chrome.storage.local.get(['autoCheckEnabled', 'notificationThreshold'], (result) => {
    autoCheckEnabled = result.autoCheckEnabled !== false; // Default to true
    notificationThreshold = result.notificationThreshold || 40; // Default to medium risk
    log('info', 'Auto-check initialized', { enabled: autoCheckEnabled, threshold: notificationThreshold });

    // Set up listeners based on loaded settings
    updateAutoCheckListeners();
  });
}

// Efficiently update auto-check listeners without re-reading settings
function updateAutoCheckListeners() {
  console.log('PhisGuard: Updating auto-check listeners', { enabled: autoCheckEnabled });

  // Remove existing listeners first
  try {
    chrome.webNavigation.onCompleted.removeListener(handleNavigationCompleted);
    chrome.webNavigation.onHistoryStateUpdated.removeListener(handleNavigationCompleted);
    console.log('PhisGuard: Removed existing listeners');
  } catch (error) {
    console.warn('PhisGuard: Error removing listeners', error);
  }

  // Add listeners only if auto-check is enabled
  if (autoCheckEnabled) {
    try {
      chrome.webNavigation.onCompleted.addListener(handleNavigationCompleted, {
        url: [{ schemes: ['http', 'https'] }]
      });

      chrome.webNavigation.onHistoryStateUpdated.addListener(handleNavigationCompleted, {
        url: [{ schemes: ['http', 'https'] }]
      });

      console.log('PhisGuard: Auto-check listeners enabled successfully');
      log('info', 'Auto-check listeners enabled');
    } catch (error) {
      console.error('PhisGuard: Failed to add navigation listeners', error);
      log('error', 'Failed to add navigation listeners', error);
    }
  } else {
    console.log('PhisGuard: Auto-check listeners disabled');
    log('info', 'Auto-check listeners disabled');
  }
}

// Listen for messages from popup/content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('PhisGuard: Message received', { action: request.action, sender: sender?.id });
  log('debug', 'Received message', { action: request.action, sender: sender.id });

  switch (request.action) {
    case 'checkUrl':
      handleUrlCheck(request.data, sendResponse);
      return true; // Keep message channel open for async response

    case 'checkSsl':
      handleSslCheck(request.data, sendResponse);
      return true;

    case 'expandLink':
      handleLinkExpansion(request.data, sendResponse);
      return true;

    case 'checkBreach':
      handleBreachCheck(request.data, sendResponse);
      return true;

    case 'comprehensiveCheck':
      handleComprehensiveCheck(request.data, sendResponse);
      return true;

    case 'getCacheStats':
      getCacheStats(sendResponse);
      return true;

    case 'clearCache':
      clearCache(sendResponse);
      return true;

    case 'getSettings':
      getSettings(sendResponse);
      return true;

    case 'updateSettings':
      updateSettings(request.data, sendResponse);
      return true;

    case 'toggleAutoCheck':
      toggleAutoCheck(request.data.enabled, sendResponse);
      return true;

    case 'ping':
      sendResponse({ success: true, pong: true });
      return true;

    case 'wakeup':
      log('debug', 'Received wakeup message');
      sendResponse({ success: true, awake: true });
      return true;

    case 'testAutoCheck':
      // Manually trigger auto-check for testing
      console.log('PhisGuard: Manual test auto-check triggered for URL:', request.data.url);
      handleNavigationCompleted({
        url: request.data.url,
        tabId: 0, // Dummy tab ID
        frameId: 0
      });
      sendResponse({ success: true });
      return true;

    default:
      sendResponse({ error: 'Unknown action' });
  }
});

// Utility function to check if we're online
function isOnline() {
  return navigator.onLine;
}

// Utility function to generate cache key
function generateCacheKey(endpoint, data) {
  return `${endpoint}_${btoa(JSON.stringify(data)).replace(/[^a-zA-Z0-9]/g, '')}`;
}

// Cache management functions
async function getCachedResult(key) {
  try {
    const result = await chrome.storage.local.get(['cache']);
    const cache = result.cache || {};
    const cached = cache[key];

    if (cached && Date.now() - cached.timestamp < CACHE_EXPIRY) {
      log('debug', 'Cache hit', { key });
      return cached.data;
    } else if (cached) {
      // Expired, remove it
      delete cache[key];
      await chrome.storage.local.set({ cache });
      log('debug', 'Cache expired, removed', { key });
    }
  } catch (error) {
    log('error', 'Error retrieving cached result', error);
  }
  return null;
}

async function setCachedResult(key, data) {
  try {
    const result = await chrome.storage.local.get(['cache']);
    const cache = result.cache || {};
    cache[key] = {
      data,
      timestamp: Date.now()
    };
    await chrome.storage.local.set({ cache });
    log('debug', 'Result cached', { key });
  } catch (error) {
    log('error', 'Error caching result', error);
  }
}

function clearExpiredCache() {
  chrome.storage.local.get(['cache'], (result) => {
    const cache = result.cache || {};
    const now = Date.now();
    let cleared = 0;

    for (const key in cache) {
      if (now - cache[key].timestamp > CACHE_EXPIRY) {
        delete cache[key];
        cleared++;
      }
    }

    if (cleared > 0) {
      chrome.storage.local.set({ cache });
      log('info', `Cleared ${cleared} expired cache entries`);
    }
  });
}

async function clearCache(sendResponse) {
  try {
    await chrome.storage.local.set({ cache: {} });
    log('info', 'Cache cleared');
    sendResponse({ success: true });
  } catch (error) {
    log('error', 'Error clearing cache', error);
    sendResponse({ error: error.message });
  }
}

async function getCacheStats(sendResponse) {
  try {
    const result = await chrome.storage.local.get(['cache']);
    const cache = result.cache || {};
    const stats = {
      totalEntries: Object.keys(cache).length,
      totalSize: JSON.stringify(cache).length,
      oldestEntry: null,
      newestEntry: null
    };

    for (const entry of Object.values(cache)) {
      if (!stats.oldestEntry || entry.timestamp < stats.oldestEntry) {
        stats.oldestEntry = entry.timestamp;
      }
      if (!stats.newestEntry || entry.timestamp > stats.newestEntry) {
        stats.newestEntry = entry.timestamp;
      }
    }

    sendResponse(stats);
  } catch (error) {
    log('error', 'Error getting cache stats', error);
    sendResponse({ error: error.message });
  }
}

// API request with retry logic
async function makeApiRequest(endpoint, data, retries = MAX_RETRIES) {
  const url = `${API_BASE_URL}${endpoint}`;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      log('debug', `API request attempt ${attempt}`, { endpoint, url });

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      log('debug', 'API request successful', { endpoint, attempt });
      return result;

    } catch (error) {
      log('warn', `API request attempt ${attempt} failed`, { endpoint, error: error.message });

      if (attempt === retries) {
        // Queue request for later if offline
        if (!isOnline()) {
          queueRequest(endpoint, data);
          throw new Error('Network unavailable, request queued');
        }
        throw error;
      }

      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY * attempt));
    }
  }
}

// Queue management
function queueRequest(endpoint, data) {
  requestQueue.push({
    endpoint,
    data,
    timestamp: Date.now(),
    id: Date.now() + Math.random()
  });
  log('info', 'Request queued for offline processing', { endpoint });
}

async function processQueuedRequests() {
  if (!isOnline() || requestQueue.length === 0) return;

  log('info', `Processing ${requestQueue.length} queued requests`);

  const remainingQueue = [];

  for (const request of requestQueue) {
    try {
      await makeApiRequest(request.endpoint, request.data, 1); // Single retry for queued requests
      log('info', 'Queued request processed successfully', { endpoint: request.endpoint });
    } catch (error) {
      // Keep in queue if still failing
      remainingQueue.push(request);
      log('warn', 'Queued request still failing, keeping in queue', { endpoint: request.endpoint, error: error.message });
    }
  }

  requestQueue = remainingQueue;

  if (requestQueue.length > 0) {
    log('info', `${requestQueue.length} requests remain in queue`);
  }
}

// Handle online/offline events
self.addEventListener('online', () => {
  log('info', 'Network connection restored');
  processQueuedRequests();
});

self.addEventListener('offline', () => {
  log('warn', 'Network connection lost');
});

// API handlers
async function handleUrlCheck(data, sendResponse) {
  const cacheKey = generateCacheKey('/check-url', data);

  try {
    // Check cache first
    let result = await getCachedResult(cacheKey);

    if (!result) {
      // Make API request
      result = await makeApiRequest('/check-url', data);

      // Cache the result
      if (result) {
        await setCachedResult(cacheKey, result);
      }
    }

    sendResponse({ success: true, data: result });
  } catch (error) {
    log('error', 'URL check failed', error);

    // Try to get cached result as fallback
    const cachedResult = await getCachedResult(cacheKey);
    if (cachedResult) {
      sendResponse({
        success: true,
        data: cachedResult,
        cached: true,
        warning: 'Using cached result due to network error'
      });
    } else {
      sendResponse({ error: error.message });
    }
  }
}

async function handleSslCheck(data, sendResponse) {
  const cacheKey = generateCacheKey('/check-ssl', data);

  try {
    let result = await getCachedResult(cacheKey);

    if (!result) {
      result = await makeApiRequest('/check-ssl', data);
      if (result) {
        await setCachedResult(cacheKey, result);
      }
    }

    sendResponse({ success: true, data: result });
  } catch (error) {
    log('error', 'SSL check failed', error);

    const cachedResult = await getCachedResult(cacheKey);
    if (cachedResult) {
      sendResponse({
        success: true,
        data: cachedResult,
        cached: true,
        warning: 'Using cached result due to network error'
      });
    } else {
      sendResponse({ error: error.message });
    }
  }
}

async function handleLinkExpansion(data, sendResponse) {
  const cacheKey = generateCacheKey('/expand-link', data);

  try {
    let result = await getCachedResult(cacheKey);

    if (!result) {
      result = await makeApiRequest('/expand-link', data);
      if (result) {
        await setCachedResult(cacheKey, result);
      }
    }

    sendResponse({ success: true, data: result });
  } catch (error) {
    log('error', 'Link expansion failed', error);

    const cachedResult = await getCachedResult(cacheKey);
    if (cachedResult) {
      sendResponse({
        success: true,
        data: cachedResult,
        cached: true,
        warning: 'Using cached result due to network error'
      });
    } else {
      sendResponse({ error: error.message });
    }
  }
}

async function handleBreachCheck(data, sendResponse) {
  const cacheKey = generateCacheKey('/check-breach', data);

  try {
    let result = await getCachedResult(cacheKey);

    if (!result) {
      result = await makeApiRequest('/check-breach', data);
      if (result) {
        await setCachedResult(cacheKey, result);
      }
    }

    sendResponse({ success: true, data: result });
  } catch (error) {
    log('error', 'Breach check failed', error);

    const cachedResult = await getCachedResult(cacheKey);
    if (cachedResult) {
      sendResponse({
        success: true,
        data: cachedResult,
        cached: true,
        warning: 'Using cached result due to network error'
      });
    } else {
      sendResponse({ error: error.message });
    }
  }
}

async function handleComprehensiveCheck(data, sendResponse) {
  const cacheKey = generateCacheKey('/comprehensive-check', data);

  try {
    let result = await getCachedResult(cacheKey);

    if (!result) {
      result = await makeApiRequest('/comprehensive-check', data);
      if (result) {
        await setCachedResult(cacheKey, result);
      }
    }

    sendResponse({ success: true, data: result });
  } catch (error) {
    log('error', 'Comprehensive check failed', error);

    const cachedResult = await getCachedResult(cacheKey);
    if (cachedResult) {
      sendResponse({
        success: true,
        data: cachedResult,
        cached: true,
        warning: 'Using cached result due to network error'
      });
    } else {
      sendResponse({ error: error.message });
    }
  }
}

// Handle navigation completion for auto-checking
async function handleNavigationCompleted(details) {
  console.log('PhisGuard: Navigation event triggered', { url: details.url, tabId: details.tabId, frameId: details.frameId });

  if (!autoCheckEnabled) {
    console.log('PhisGuard: Auto-check disabled, skipping');
    return;
  }

  const url = details.url;
  const tabId = details.tabId;
  const now = Date.now();

  // Throttle checks to prevent rate limiting
  if (now - lastCheckTime < CHECK_THROTTLE_MS) {
    console.log('PhisGuard: Check throttled, too soon since last check');
    return;
  }

  // Skip if we've recently checked this URL
  if (lastCheckedUrls.has(url)) {
    console.log('PhisGuard: URL recently checked, skipping', url);
    return;
  }

  // Skip internal Chrome pages and extensions
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
      url.startsWith('about:') || url.startsWith('data:') ||
      url.startsWith('file://') || url.startsWith('javascript:')) {
    console.log('PhisGuard: Skipping internal URL', url);
    return;
  }

  // Skip URLs that are too short or don't have proper structure
  if (url.length < 10 || !url.includes('.')) {
    console.log('PhisGuard: Skipping invalid URL format', url);
    return;
  }

  // Skip if it's a subframe (iframe)
  if (details.frameId !== 0) {
    console.log('PhisGuard: Skipping subframe', { url, frameId: details.frameId });
    return;
  }

  console.log('PhisGuard: Starting auto-check for page', { url, tabId });
  lastCheckTime = now;

  try {
    // Perform comprehensive check
    const result = await performAutoCheck(url);

    if (result) {
      console.log('PhisGuard: Auto-check completed', {
        url,
        score: result.overall_score,
        level: result.risk_level
      });

      // Add to recently checked URLs
      lastCheckedUrls.add(url);

      // Clean up old entries (keep last 50)
      if (lastCheckedUrls.size > 50) {
        const urlsArray = Array.from(lastCheckedUrls);
        lastCheckedUrls = new Set(urlsArray.slice(-50));
      }

      // Show notification if risk is above threshold
      if (result.overall_score >= notificationThreshold) {
        console.log('PhisGuard: Showing notification for risky page', {
          url,
          score: result.overall_score,
          threshold: notificationThreshold
        });
        await showSecurityNotification(url, result, tabId);
      } else {
        console.log('PhisGuard: Page risk below threshold, no notification', {
          url,
          score: result.overall_score,
          threshold: notificationThreshold
        });
      }
    }
  } catch (error) {
    console.error('PhisGuard: Auto-check failed', { url, error: error.message });
  }
}

// Perform automatic comprehensive security check
async function performAutoCheck(url) {
  try {
    // Get all security data
    const [urlResult, sslResult, linkResult] = await Promise.allSettled([
      makeApiRequest('/check-url', { url }),
      makeApiRequest('/check-ssl', { url }),
      makeApiRequest('/expand-link', { url })
    ]);

    const results = {
      url: urlResult.status === 'fulfilled' ? urlResult.value : null,
      ssl: sslResult.status === 'fulfilled' ? sslResult.value : null,
      link: linkResult.status === 'fulfilled' ? linkResult.value : null
    };

    // Calculate overall risk using risk scorer
    const overallRisk = calculateOverallRisk(results);

    log('info', 'Auto-check completed', {
      url,
      overall_score: overallRisk.overall_score,
      risk_level: overallRisk.risk_level
    });

    return overallRisk;

  } catch (error) {
    log('error', 'Auto-check error', { url, error: error.message });
    return null;
  }
}

// Calculate overall risk from individual checks
function calculateOverallRisk(results) {
  let totalScore = 0;
  let components = [];

  // URL risk (40% weight)
  if (results.url) {
    const urlScore = results.url.risk_score || 0;
    totalScore += urlScore * 0.4;
    components.push(`URL: ${urlScore}/100`);
  }

  // SSL risk (30% weight)
  if (results.ssl) {
    const sslScore = results.ssl.risk_score || 0;
    totalScore += sslScore * 0.3;
    components.push(`SSL: ${sslScore}/100`);
  }

  // Link risk (30% weight)
  if (results.link && results.link.analysis) {
    const linkScore = results.link.analysis.risk_score || 0;
    totalScore += linkScore * 0.3;
    components.push(`Links: ${linkScore}/100`);
  }

  const overallScore = Math.min(100, Math.max(0, totalScore));

  let riskLevel = 'very_low';
  if (overallScore >= 70) riskLevel = 'high';
  else if (overallScore >= 40) riskLevel = 'medium';
  else if (overallScore >= 20) riskLevel = 'low';

  return {
    overall_score: Math.round(overallScore),
    risk_level: riskLevel,
    components: components,
    details: results
  };
}

// Show user-friendly security notification
async function showSecurityNotification(url, riskData, tabId) {
  try {
    const notificationId = `phisguard_${Date.now()}`;

    let title, message, icon;

    switch (riskData.risk_level) {
      case 'high':
        title = '🚨 High Security Risk Detected';
        message = 'This page has significant security concerns. Proceed with caution!';
        icon = 'warning';
        break;
      case 'medium':
        title = '⚠️ Security Concerns Found';
        message = 'This page has some security issues. Please review before proceeding.';
        icon = 'caution';
        break;
      case 'low':
        title = 'ℹ️ Minor Security Notes';
        message = 'This page has minor security considerations.';
        icon = 'info';
        break;
      default:
        return; // Don't show notification for very low risk
    }

    // Create notification
    await chrome.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icon.png'), // You'll need to add an icon
      title: title,
      message: message,
      contextMessage: `Risk Score: ${riskData.overall_score}/100`,
      buttons: [
        { title: 'View Details' },
        { title: 'Open PhisGuard' }
      ],
      requireInteraction: riskData.risk_level === 'high'
    });

    // Store notification data for button clicks
    chrome.storage.local.set({
      [`notification_${notificationId}`]: {
        url,
        riskData,
        tabId,
        timestamp: Date.now()
      }
    });

    log('info', 'Security notification shown', { url, riskLevel: riskData.risk_level });

  } catch (error) {
    log('error', 'Failed to show notification', error);
  }
}

// Handle notification button clicks
chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
  if (!notificationId.startsWith('phisguard_')) return;

  try {
    const result = await chrome.storage.local.get([`notification_${notificationId}`]);
    const data = result[`notification_${notificationId}`];

    if (!data) return;

    if (buttonIndex === 0) {
      // View Details - open popup with details
      await chrome.windows.create({
        url: chrome.runtime.getURL('popup.html') + `?url=${encodeURIComponent(data.url)}&autoCheck=true`,
        type: 'popup',
        width: 500,
        height: 600
      });
    } else if (buttonIndex === 1) {
      // Open PhisGuard - focus the popup
      chrome.action.openPopup();
    }

    // Clean up stored notification data
    chrome.storage.local.remove([`notification_${notificationId}`]);

  } catch (error) {
    log('error', 'Error handling notification click', error);
  }
});

// Clean up old notification data periodically
setInterval(() => {
  chrome.storage.local.get(null, (items) => {
    const now = Date.now();
    const toRemove = [];

    for (const key in items) {
      if (key.startsWith('notification_') && items[key].timestamp) {
        if (now - items[key].timestamp > 5 * 60 * 1000) { // 5 minutes
          toRemove.push(key);
        }
      }
    }

    if (toRemove.length > 0) {
      chrome.storage.local.remove(toRemove);
    }
  });
}, 60 * 1000); // Check every minute

// Settings management functions
async function getSettings(sendResponse) {
  try {
    const result = await chrome.storage.local.get(['autoCheckEnabled', 'notificationThreshold']);
    const settings = {
      autoCheckEnabled: result.autoCheckEnabled !== false,
      notificationThreshold: result.notificationThreshold || 40
    };
    sendResponse({ success: true, data: settings });
  } catch (error) {
    log('error', 'Error getting settings', error);
    sendResponse({ error: error.message });
  }
}

async function updateSettings(settings, sendResponse) {
  const startTime = Date.now();
  log('debug', 'Starting settings update', { settings });

  try {
    // Batch all storage operations
    const storageUpdate = {};

    if (settings.autoCheckEnabled !== undefined) {
      storageUpdate.autoCheckEnabled = settings.autoCheckEnabled;
    }

    if (settings.notificationThreshold !== undefined) {
      storageUpdate.notificationThreshold = settings.notificationThreshold;
    }

    // Single storage operation
    if (Object.keys(storageUpdate).length > 0) {
      log('debug', 'Performing storage update', { storageUpdate });
      await chrome.storage.local.set(storageUpdate);
      log('debug', 'Storage update completed');
    }

    // Update global variables efficiently
    if (settings.autoCheckEnabled !== undefined) {
      const wasEnabled = autoCheckEnabled;
      autoCheckEnabled = settings.autoCheckEnabled;
      log('debug', 'Auto-check enabled changed', { from: wasEnabled, to: autoCheckEnabled });

      // Only re-initialize if the state actually changed
      if (wasEnabled !== autoCheckEnabled) {
        log('debug', 'Updating auto-check listeners');
        updateAutoCheckListeners();
      }
    }

    if (settings.notificationThreshold !== undefined) {
      notificationThreshold = settings.notificationThreshold;
      log('debug', 'Notification threshold updated', { threshold: notificationThreshold });
    }

    const duration = Date.now() - startTime;
    log('info', 'Settings updated successfully', { duration, settings });
    sendResponse({ success: true });
  } catch (error) {
    const duration = Date.now() - startTime;
    log('error', 'Error updating settings', { error: error.message, duration, settings });
    sendResponse({ error: error.message });
  }
}

async function toggleAutoCheck(enabled, sendResponse) {
  try {
    await chrome.storage.local.set({ autoCheckEnabled: enabled });
    autoCheckEnabled = enabled;

    // Use the efficient listener update function
    updateAutoCheckListeners();

    sendResponse({ success: true, enabled });
  } catch (error) {
    log('error', 'Error toggling auto-check', error);
    sendResponse({ error: error.message });
  }
}

// Periodic cleanup of expired cache entries
setInterval(clearExpiredCache, 60 * 60 * 1000); // Every hour