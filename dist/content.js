// PhisGuard Content Script
// Automatically scans links for security risks and adds visual indicators

// CSS is injected via manifest.json content_scripts

// Function to check a single link via background script
async function checkLink(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: 'checkUrl', data: { url } }, (response) => {
      resolve(response);
    });
  });
}

// Function to add visual indicators and tooltips to a link
function addIndicator(link, riskData) {
  // Remove existing indicators
  const existingIndicator = link.parentNode.querySelector('.phisguard-indicator');
  if (existingIndicator) existingIndicator.remove();

  const existingTooltip = link.parentNode.querySelector('.phisguard-tooltip');
  if (existingTooltip) existingTooltip.remove();

  const existingAction = link.parentNode.querySelector('.phisguard-quick-action');
  if (existingAction) existingAction.remove();

  // Create indicator element
  const indicator = document.createElement('span');
  indicator.className = 'phisguard-indicator';

  // Add link class for highlighting
  link.classList.add('phisguard-link');

  // Determine risk level and styling
  let icon = '';
  let tooltipText = '';
  let riskClass = '';

  if (riskData.risk_level === 'high') {
    riskClass = 'high-risk';
    icon = '⚠️';
    tooltipText = `High Risk: ${riskData.details || 'This link appears suspicious'}`;
  } else if (riskData.risk_level === 'medium') {
    riskClass = 'medium-risk';
    icon = '⚡';
    tooltipText = `Medium Risk: ${riskData.details || 'This link may be risky'}`;
  } else {
    riskClass = 'safe';
    icon = '✅';
    tooltipText = 'Safe: This link appears secure';
  }

  indicator.classList.add(riskClass);
  indicator.innerHTML = icon;
  indicator.title = tooltipText;

  link.classList.add(riskClass);

  // Create tooltip element
  const tooltip = document.createElement('div');
  tooltip.className = 'phisguard-tooltip';
  tooltip.textContent = tooltipText;

  // Show tooltip on hover
  indicator.addEventListener('mouseenter', (e) => {
    tooltip.style.display = 'block';
    tooltip.style.left = `${e.pageX + 10}px`;
    tooltip.style.top = `${e.pageY + 10}px`;
    document.body.appendChild(tooltip);
  });

  indicator.addEventListener('mouseleave', () => {
    tooltip.style.display = 'none';
    if (tooltip.parentNode) tooltip.parentNode.removeChild(tooltip);
  });

  // Create quick action button
  const actionButton = document.createElement('button');
  actionButton.className = 'phisguard-quick-action';
  actionButton.textContent = 'Details';
  actionButton.addEventListener('click', () => {
    // Open popup with details or send message to background
    chrome.runtime.sendMessage({
      action: 'comprehensiveCheck',
      data: { url: link.href }
    }, (response) => {
      if (response.success) {
        alert(`Detailed Analysis:\n${JSON.stringify(response.data, null, 2)}`);
      } else {
        alert('Error fetching details');
      }
    });
  });

  // Insert elements before the link
  link.parentNode.insertBefore(indicator, link);
  link.parentNode.insertBefore(actionButton, link.nextSibling);
}

// Function to process a batch of links
async function processLinks(links) {
  const validLinks = Array.from(links).filter(link => {
    const url = link.href;
    return url && !url.startsWith('javascript:') && !url.startsWith('mailto:') && !url.startsWith('#');
  });

  // Process links in batches to avoid overwhelming the background script
  const batchSize = 5;
  for (let i = 0; i < validLinks.length; i += batchSize) {
    const batch = validLinks.slice(i, i + batchSize);
    await Promise.all(batch.map(async (link) => {
      try {
        const response = await checkLink(link.href);
        if (response && response.success) {
          addIndicator(link, response.data);
        }
      } catch (error) {
        console.error('PhisGuard: Error checking link', link.href, error);
      }
    }));
    // Small delay between batches
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}

// Initial scan on page load
document.addEventListener('DOMContentLoaded', () => {
  const links = document.querySelectorAll('a');
  processLinks(links);
});

// Handle dynamic content with MutationObserver
const observer = new MutationObserver((mutations) => {
  const newLinks = [];
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        if (node.tagName === 'A') {
          newLinks.push(node);
        } else {
          const links = node.querySelectorAll ? node.querySelectorAll('a') : [];
          newLinks.push(...links);
        }
      }
    });
  });

  if (newLinks.length > 0) {
    // Debounce processing of new links
    clearTimeout(window.phisguardDebounce);
    window.phisguardDebounce = setTimeout(() => {
      processLinks(newLinks);
    }, 500);
  }
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

// Listen for messages from background script (if needed for updates)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'refreshIndicators') {
    // Re-scan all links
    const links = document.querySelectorAll('a');
    processLinks(links);
  }
});