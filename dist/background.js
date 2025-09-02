// PhisGuard Background Service Worker
// Handles API communication, caching, and offline functionality

const API_BASE_URL = 'http://localhost:5000';
const CACHE_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second

// Request queue for offline handling
let requestQueue = [];

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
      cacheEnabled: true
    },
    logs: []
  });

  // Clear old cache entries on update
  if (details.reason === 'update') {
    clearExpiredCache();
  }
});

// Handle extension startup
chrome.runtime.onStartup.addListener(() => {
  log('info', 'PhisGuard service worker started');
  processQueuedRequests();
});

// Listen for messages from popup/content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
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
window.addEventListener('online', () => {
  log('info', 'Network connection restored');
  processQueuedRequests();
});

window.addEventListener('offline', () => {
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

// Periodic cleanup of expired cache entries
setInterval(clearExpiredCache, 60 * 60 * 1000); // Every hour