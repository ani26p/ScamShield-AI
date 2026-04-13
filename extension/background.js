// ScamShield Background Service Worker (MV3)
// Minimal — keeps the extension alive and handles any future messaging.

chrome.runtime.onInstalled.addListener(() => {
  console.log('[ScamShield] Extension installed.');
});
