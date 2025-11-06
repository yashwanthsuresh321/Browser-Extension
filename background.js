// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
    console.log("Extension installed");
});

// Debug: Check if rules are being applied
chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    console.log("Rule matched:", info);
});

// Simple message listener for potential future use
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "ping") {
        sendResponse({status: "active"});
    }
    return true;
});