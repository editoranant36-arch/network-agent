// LAN Sentinel - Background Service Worker

chrome.runtime.onInstalled.addListener(() => {
  console.log("LAN Sentinel Network Scanner extension installed successfully.");
});

// Listener for messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scanLocalAgent") {
    fetch("http://127.0.0.1:8080/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request.payload || { cidr: "192.168.0.0/24" })
    })
      .then((r) => r.json())
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep message channel open for async response
  }
});
