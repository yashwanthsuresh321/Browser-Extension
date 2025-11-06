// Constants for direct communication
const TOOL_BASE_URL = "http://localhost:8765"; // Base URL for desktop tool communication
const MAX_RETRIES = 3; // Maximum retry attempts for failed requests
const RETRY_DELAY = 1000; // Delay between retries in milliseconds

// Function to check tool connection
async function checkToolConnection() {
    try {
        const response = await fetch(`${TOOL_BASE_URL}/api/status`, { // Send GET request to status endpoint
            method: 'GET',
            headers: {
                'Content-Type': 'application/json' // Set JSON content type
            }
        });
        
        if (response.ok) { // If response is successful
            const data = await response.json(); // Parse JSON response
            return { connected: true, data }; // Return connection success with data
        }
    } catch (error) {
        console.log("Tool connection failed:", error); // Log connection failure
    }
    return { connected: false }; // Return connection failure
}

// Function to send history directly to tool
async function sendHistoryToTool(historyData) {
    let retries = 0; // Initialize retry counter
    
    while (retries < MAX_RETRIES) { // Loop until max retries reached
        try {
            const response = await fetch(`${TOOL_BASE_URL}/api/history`, { // Send POST request with history data
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json', // Set JSON content type
                },
                body: JSON.stringify(historyData) // Convert history data to JSON string
            });
            
            if (response.ok) { // If request successful
                const result = await response.json(); // Parse response JSON
                return { success: true, data: result }; // Return success with result data
            }
        } catch (error) {
            console.log(`Attempt ${retries + 1} failed:`, error); // Log failed attempt
        }
        
        retries++; // Increment retry counter
        if (retries < MAX_RETRIES) {
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY)); // Wait before retrying
        }
    }
    
    return { success: false, error: "Failed to connect to desktop tool after multiple attempts" }; // Return failure after all retries
}

// Function to get malicious domains from tool
async function getMaliciousDomainsFromTool() {
    try {
        const response = await fetch(`${TOOL_BASE_URL}/api/import`, { // Send GET request to import endpoint
            method: 'GET',
            headers: {
                'Content-Type': 'application/json' // Set JSON content type
            }
        });
        
        if (response.ok) { // If response successful
            const data = await response.json(); // Parse JSON response
            return { success: true, domains: data.domains || [] }; // Return success with domains array
        }
    } catch (error) {
        console.log("Failed to get domains from tool:", error); // Log failure
    }
    return { success: false, domains: [] }; // Return failure with empty domains
}

// Function to show status messages
function showStatus(message, isError = false) {
    const status = document.getElementById("status"); // Get status element
    if (status) {
        status.textContent = message; // Set status text
        status.className = isError ? "status error" : "status"; // Set CSS class based on error state
    }
}

// Function to extract domain from URL
function extractDomain(url) {
    try {
        // Handle URL-encoded strings
        const decodedUrl = decodeURIComponent(url); // Decode URL-encoded characters
        const urlObj = new URL(decodedUrl); // Create URL object for parsing
        let domain = urlObj.hostname; // Extract hostname (domain)
        
        // Remove www prefix if present
        if (domain.startsWith('www.')) {
            domain = domain.substring(4); // Remove 'www.' prefix
        }
        return domain; // Return cleaned domain
    } catch (e) {
        // If it's not a valid URL, try to extract domain manually
        const cleanUrl = url.replace(/^https?:\/\//, '').split('/')[0]; // Remove protocol and path
        return cleanUrl.replace(/^www\./, ''); // Remove www prefix and return
    }
}

// Function to generate unique rule IDs
function generateRuleId() {
    return Math.floor(Math.random() * 10000) + 1000; // Generate random ID between 1000-10999
}

// Function to block a domain
function blockDomain(domain) {
    const cleanDomain = extractDomain(domain); // Extract and clean domain from input
    if (!cleanDomain) {
        console.error("Invalid domain:", domain); // Log invalid domain error
        return Promise.reject("Invalid domain"); // Reject promise with error
    }
    
    const ruleId = generateRuleId(); // Generate unique rule ID
    const rule = {
        id: ruleId, // Set rule ID
        priority: 1, // Set rule priority
        action: { type: "block" }, // Set action to block
        condition: { 
            urlFilter: `||${cleanDomain}^`, // Match any URL from this domain
            resourceTypes: ["main_frame", "sub_frame", "script", "xmlhttprequest"] // Apply to these resource types
        }
    };

    return new Promise((resolve, reject) => {
        chrome.declarativeNetRequest.updateDynamicRules({
            addRules: [rule] // Add the blocking rule
        }, () => {
            if (chrome.runtime.lastError) { // Check for Chrome API error
                reject(chrome.runtime.lastError); // Reject promise with error
                return;
            }
            
            // Save to storage for tracking
            chrome.storage.local.get({blockedDomains: {}}, (result) => {
                const blockedDomains = result.blockedDomains; // Get current blocked domains
                blockedDomains[cleanDomain] = ruleId; // Add new domain with rule ID
                chrome.storage.local.set({blockedDomains}, () => { // Save updated blocked domains
                    if (chrome.runtime.lastError) { // Check for storage error
                        reject(chrome.runtime.lastError); // Reject promise with error
                    } else {
                        resolve(ruleId); // Resolve promise with rule ID
                    }
                });
            });
        });
    });
}

// FIXED: Function to unblock a domain - IMPROVED VERSION
function unblockDomain(domain) {
    const cleanDomain = extractDomain(domain); // Extract and clean domain
    
    return new Promise((resolve, reject) => {
        chrome.storage.local.get({blockedDomains: {}}, (result) => {
            const blockedDomains = result.blockedDomains; // Get current blocked domains
            
            console.log("Current blocked domains:", Object.keys(blockedDomains)); // DEBUG: Log current domains
            console.log("Looking for domain to unblock:", cleanDomain); // DEBUG: Log target domain
            
            // Check if domain exists exactly in storage
            if (blockedDomains[cleanDomain]) {
                const ruleId = blockedDomains[cleanDomain]; // Get rule ID for domain
                
                console.log(`Found exact match: ${cleanDomain} with rule ID: ${ruleId}`); // DEBUG: Log exact match
                
                // Remove the rule
                chrome.declarativeNetRequest.updateDynamicRules({
                    removeRuleIds: [ruleId] // Remove rule by ID
                }, () => {
                    if (chrome.runtime.lastError) {
                        console.error("Error removing rule:", chrome.runtime.lastError); // Log rule removal error
                        reject(chrome.runtime.lastError); // Reject promise with error
                        return;
                    }
                    
                    console.log(`Successfully removed rule ${ruleId} for domain ${cleanDomain}`); // DEBUG: Log success
                    
                    // Remove from storage
                    delete blockedDomains[cleanDomain]; // Delete domain from storage object
                    chrome.storage.local.set({blockedDomains}, () => { // Save updated storage
                        if (chrome.runtime.lastError) {
                            console.error("Error updating storage:", chrome.runtime.lastError); // Log storage error
                            reject(chrome.runtime.lastError); // Reject promise with error
                        } else {
                            console.log(`Successfully removed ${cleanDomain} from storage`); // DEBUG: Log storage success
                            resolve(); // Resolve promise successfully
                        }
                    });
                });
            } else {
                // IMPROVED: Try to find the domain by checking all stored domains more carefully
                let foundDomain = null;
                let foundRuleId = null;
                
                console.log("No exact match found, searching through all domains..."); // DEBUG: Log search start
                
                for (const [storedDomain, storedRuleId] of Object.entries(blockedDomains)) {
                    console.log(`Checking stored domain: "${storedDomain}" against target: "${cleanDomain}"`); // DEBUG: Log comparison
                    
                    // Multiple matching strategies
                    if (storedDomain === cleanDomain || 
                        storedDomain.includes(cleanDomain) || 
                        cleanDomain.includes(storedDomain) ||
                        extractDomain(storedDomain) === cleanDomain) {
                        
                        foundDomain = storedDomain;
                        foundRuleId = storedRuleId;
                        console.log(`✅ Found domain match: "${foundDomain}" with rule ID: ${foundRuleId}`); // DEBUG: Log found match
                        break; // Stop searching once found
                    }
                }
                
                if (foundDomain && foundRuleId) {
                    console.log(`Removing matched domain: ${foundDomain} with rule ID: ${foundRuleId}`); // DEBUG: Log removal start
                    
                    // Remove the rule
                    chrome.declarativeNetRequest.updateDynamicRules({
                        removeRuleIds: [foundRuleId] // Remove found rule
                    }, () => {
                        if (chrome.runtime.lastError) {
                            reject(chrome.runtime.lastError); // Reject promise with error
                            return;
                        }
                        
                        // Remove from storage
                        delete blockedDomains[foundDomain]; // Delete found domain
                        chrome.storage.local.set({blockedDomains}, () => { // Save updated storage
                            if (chrome.runtime.lastError) {
                                reject(chrome.runtime.lastError); // Reject promise with error
                            } else {
                                console.log(`✅ Successfully unblocked domain: ${foundDomain}`); // DEBUG: Log success
                                resolve(); // Resolve promise successfully
                            }
                        });
                    });
                } else {
                    console.error(`❌ Domain "${cleanDomain}" not found in blocklist. Current blocked domains:`, Object.keys(blockedDomains)); // Log domain not found
                    
                    // FALLBACK: Try to get all rules and find matching ones
                    chrome.declarativeNetRequest.getDynamicRules((rules) => {
                        console.log("All current rules:", rules); // DEBUG: Log all rules
                        
                        const matchingRules = rules.filter(rule => {
                            if (rule.condition && rule.condition.urlFilter) {
                                const urlFilter = rule.condition.urlFilter;
                                // Check if this rule matches our domain
                                return urlFilter.includes(cleanDomain) || 
                                       cleanDomain.includes(urlFilter.replace('||', '').replace('^', ''));
                            }
                            return false;
                        });
                        
                        if (matchingRules.length > 0) {
                            console.log(`Found ${matchingRules.length} matching rules for domain ${cleanDomain}`); // DEBUG: Log matching rules
                            const ruleIds = matchingRules.map(rule => rule.id); // Extract rule IDs
                            
                            // Remove all matching rules
                            chrome.declarativeNetRequest.updateDynamicRules({
                                removeRuleIds: ruleIds // Remove all matching rules
                            }, () => {
                                if (chrome.runtime.lastError) {
                                    reject(chrome.runtime.lastError); // Reject promise with error
                                } else {
                                    // Also clean up storage by removing any domains that might match
                                    let updated = false;
                                    for (const domainKey in blockedDomains) {
                                        if (domainKey.includes(cleanDomain) || cleanDomain.includes(domainKey)) {
                                            delete blockedDomains[domainKey]; // Remove matching domain from storage
                                            updated = true;
                                        }
                                    }
                                    
                                    if (updated) {
                                        chrome.storage.local.set({blockedDomains}, () => { // Save cleaned storage
                                            resolve(); // Resolve promise successfully
                                        });
                                    } else {
                                        resolve(); // Resolve even if no storage update needed
                                    }
                                }
                            });
                        } else {
                            reject("Domain not found in blocklist and no matching rules found"); // Reject with detailed error
                        }
                    });
                }
            }
        });
    });
}

// Function to show blocklist management
function showBlocklistManagement() {
    chrome.storage.local.get({blockedDomains: {}}, (result) => {
        const blockedDomains = result.blockedDomains; // Get current blocked domains
        const domains = Object.keys(blockedDomains); // Extract domain names
        
        // Remove existing management UI if any
        const existingManagement = document.getElementById('blocklistManagement'); // Find existing UI
        if (existingManagement) {
            existingManagement.remove(); // Remove existing UI
        }

        if (domains.length === 0) { // Check if no domains are blocked
            showStatus("No domains are currently blocked."); // Show status message
            return; // Exit function
        }

        // Create management UI
        const managementDiv = document.createElement("div"); // Create container div
        managementDiv.id = "blocklistManagement"; // Set ID for future reference
        managementDiv.style.marginTop = "20px"; // Add top margin
        managementDiv.style.padding = "15px"; // Add padding
        managementDiv.style.border = "1px solid #ddd"; // Add border
        managementDiv.style.borderRadius = "5px"; // Round corners
        managementDiv.style.backgroundColor = "#f8f9fa"; // Set background color
        
        managementDiv.innerHTML = `
            <h3 style="margin-bottom: 15px; color: #333;">Currently Blocked Domains (${domains.length})</h3>
            <div class="blocked-list" style="max-height: 300px; overflow-y: auto;">
                ${domains.map(domain => `
                    <div class="blocked-item" style="display: flex; justify-content: space-between; align-items: center; padding: 10px; border-bottom: 1px solid #eee; background: white;">
                        <span style="font-family: monospace; font-size: 12px;">${domain}</span>
                        <button class="remove-btn" data-domain="${domain}" style="background-color: #ff4757; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px;">
                            Remove
                        </button>
                    </div>
                `).join('')} <!-- Generate HTML for each blocked domain -->
            </div>
            <div style="margin-top: 15px;">
                <button id="resetAllBtn" style="padding: 8px 16px; background-color: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px;">
                    Reset All Blocking
                </button>
                <button id="closeManagement" style="padding: 8px 16px; background-color: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer;">
                    Close
                </button>
            </div>
        `;

        // Add event listeners with timeout to ensure DOM is ready
        setTimeout(() => {
            const removeButtons = managementDiv.querySelectorAll('.remove-btn'); // Get all remove buttons
            removeButtons.forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    const domain = e.target.getAttribute('data-domain'); // Get domain from button attribute
                    console.log(`🔄 Attempting to remove domain: ${domain}`); // DEBUG: Log removal attempt
                    
                    // Disable button during processing
                    e.target.disabled = true; // Disable button
                    e.target.textContent = "Removing..."; // Change button text
                    e.target.style.backgroundColor = "#95a5a6"; // Change button color
                    
                    try {
                        await unblockDomain(domain); // Call unblock function
                        showStatus(`✅ Removed ${domain} from blocklist`); // Show success status
                        
                        // Refresh management view with a slight delay to ensure rules are updated
                        setTimeout(() => {
                            managementDiv.remove(); // Remove current management UI
                            showBlocklistManagement(); // Refresh management view
                        }, 500); // Wait 500ms before refresh
                        
                    } catch (error) {
                        console.error(`❌ Error removing domain ${domain}:`, error); // Log error
                        showStatus(`❌ Error removing domain: ${error}`, true); // Show error status
                        
                        // Re-enable button on error
                        e.target.disabled = false; // Re-enable button
                        e.target.textContent = "Remove"; // Reset button text
                        e.target.style.backgroundColor = "#ff4757"; // Reset button color
                    }
                });
            });

            // Add event listener for reset all button
            managementDiv.querySelector('#resetAllBtn').addEventListener('click', () => {
                if (confirm("Are you sure you want to remove ALL blocked domains?")) { // Confirm reset
                    chrome.declarativeNetRequest.getDynamicRules((rules) => { // Get all current rules
                        const ruleIds = rules.map(rule => rule.id); // Extract all rule IDs
                        chrome.declarativeNetRequest.updateDynamicRules({
                            removeRuleIds: ruleIds // Remove all rules
                        }, () => {
                            chrome.storage.local.set({blockedDomains: {}}, () => { // Clear storage
                                showStatus("✅ All domains unblocked"); // Show success status
                                managementDiv.remove(); // Remove management UI
                            });
                        });
                    });
                }
            });

            // Add event listener for close button
            managementDiv.querySelector('#closeManagement').addEventListener('click', () => {
                managementDiv.remove(); // Remove management UI
            });
        }, 100); // Wait 100ms before adding event listeners

        // Add to page
        document.body.appendChild(managementDiv); // Append management UI to document body
    });
}

// Helper function for file import
function triggerFileImport() {
    const fileInput = document.createElement('input'); // Create file input element
    fileInput.type = 'file'; // Set input type to file
    fileInput.accept = '.json,.txt'; // Accept JSON and text files
    
    fileInput.addEventListener('change', (event) => {
        const file = event.target.files[0]; // Get selected file
        if (!file) return; // Exit if no file selected
        
        const reader = new FileReader(); // Create file reader
        reader.onload = (e) => {
            try {
                const content = e.target.result; // Get file content
                let domains = []; // Initialize domains array
                
                // Try to parse as JSON
                try {
                    const data = JSON.parse(content); // Parse JSON content
                    
                    if (Array.isArray(data)) {
                        // Simple array of domains/URLs
                        domains = data.map(item => extractDomain(item)).filter(domain => domain); // Extract domains
                    } else if (data.domains && Array.isArray(data.domains)) {
                        // Structured JSON with domains array
                        domains = data.domains.map(domain => extractDomain(domain)).filter(domain => domain); // Extract domains
                    } else if (data.rules && Array.isArray(data.rules)) {
                        // DNR rules format
                        domains = data.rules.map(rule => {
                            if (rule.condition && rule.condition.urlFilter) {
                                const urlFilter = rule.condition.urlFilter; // Get URL filter
                                if (urlFilter.startsWith('||') && urlFilter.endsWith('^')) {
                                    return urlFilter.substring(2, urlFilter.length - 1); // Extract domain from filter
                                }
                            }
                            return null; // Return null for invalid rules
                        }).filter(domain => domain); // Filter out null values
                    }
                } catch (jsonError) {
                    // If not JSON, treat as text with one domain per line
                    domains = content.split('\n') // Split by new lines
                        .map(line => line.trim()) // Trim each line
                        .filter(line => line && !line.startsWith('#')) // Filter out empty lines and comments
                        .map(line => extractDomain(line)) // Extract domain from each line
                        .filter(domain => domain); // Filter out invalid domains
                }
                
                if (domains.length === 0) { // Check if no valid domains found
                    showStatus("No valid domains found in file", true); // Show error status
                    return; // Exit function
                }
                
                // Process domains sequentially
                const processDomains = async () => {
                    let successCount = 0; // Initialize success counter
                    let errorCount = 0; // Initialize error counter
                    
                    showStatus(`Blocking ${domains.length} domains...`); // Show progress status
                    
                    for (const domain of domains) { // Loop through each domain
                        try {
                            await blockDomain(domain); // Block the domain
                            successCount++; // Increment success counter
                            // Small delay between blocks to avoid rate limiting
                            await new Promise(resolve => setTimeout(resolve, 50)); // Wait 50ms
                        } catch (error) {
                            console.error("Failed to block domain:", domain, error); // Log blocking error
                            errorCount++; // Increment error counter
                        }
                    }
                    
                    showStatus(`✅ Successfully blocked ${successCount} out of ${domains.length} domains${errorCount > 0 ? ` (${errorCount} failed)` : ''}`); // Show final status
                };
                
                processDomains(); // Start domain processing
            } catch (error) {
                showStatus("Error processing file: " + error.message, true); // Show file processing error
            }
        };
        
        reader.readAsText(file); // Read file as text
    });
    
    fileInput.click(); // Trigger file input click
}

// Main event listener when DOM content is loaded
document.addEventListener("DOMContentLoaded", () => {
    const analyzeBtn = document.getElementById("analyzeBtn"); // Get analyze button
    const directImportBtn = document.getElementById("directImportBtn"); // Get direct import button
    const importBtn = document.getElementById("importBtn"); // Get import button
    const manageBtn = document.getElementById("manageBlocklistBtn"); // Get manage blocklist button
    const status = document.getElementById("status"); // Get status element
    const downloadArea = document.getElementById("downloadArea"); // Get download area
    const connectionStatus = document.getElementById("connectionStatus"); // Get connection status

    // Check tool connection on load
    checkToolConnection().then(({ connected, data }) => {
        if (connected) {
            showStatus("Desktop tool connected and ready", false); // Show connected status
            connectionStatus.textContent = "Connected to desktop tool"; // Update connection status text
            connectionStatus.className = "connection-status connected"; // Set connected CSS class
            console.log("Tool status:", data); // Log tool status data
        } else {
            showStatus("Desktop tool not detected. Using file-based workflow.", true); // Show disconnected status
            connectionStatus.textContent = "Desktop tool not connected"; // Update connection status text
            connectionStatus.className = "connection-status disconnected"; // Set disconnected CSS class
        }
    });

    // Generate history file (File workflow)
    analyzeBtn.addEventListener("click", () => {
        showStatus("Fetching history..."); // Show fetching status
        downloadArea.innerHTML = ""; // Clear download area

        chrome.history.search({ // Search browser history
            text: "", // Empty search text (get all history)
            maxResults: 500, // Maximum 500 results
            startTime: 0 // Start from beginning of time
        }, (results) => {
            if (!results || results.length === 0) { // Check if no history found
                showStatus("No history found."); // Show no history status
                return; // Exit function
            }

            // Create CSV file
            let csvContent = "URL,Title,VisitCount,LastVisitTime\n"; // CSV header row
            results.forEach((item) => {
                const safeUrl = `"${(item.url || '').replace(/"/g, '""')}"`; // Escape quotes in URL
                const safeTitle = `"${(item.title || 'No Title').replace(/"/g, '""')}"`; // Escape quotes in title
                const visitCount = item.visitCount || 1; // Default to 1 if no visit count
                const lastVisitTime = item.lastVisitTime || Date.now(); // Default to current time if no timestamp
                
                csvContent += `${safeUrl},${safeTitle},${visitCount},${lastVisitTime}\n`; // Add row to CSV
            });
            
            const blob = new Blob([csvContent], { type: "text/csv" }); // Create CSV blob
            const url = URL.createObjectURL(blob); // Create object URL for blob

            const a = document.createElement("a"); // Create download link
            a.href = url; // Set href to blob URL
            a.download = "browser_history.csv"; // Set download filename
            a.textContent = "Download History CSV"; // Set link text
            a.className = "download-link"; // Set CSS class
            a.style.display = "block"; // Set display style
            a.style.margin = "10px 0"; // Set margin style
            a.style.padding = "8px"; // Set padding style
            a.style.backgroundColor = "#4361ee"; // Set background color
            a.style.color = "white"; // Set text color
            a.style.textDecoration = "none"; // Remove underline
            a.style.borderRadius = "4px"; // Round corners
            a.style.textAlign = "center"; // Center text

            downloadArea.appendChild(a); // Add download link to area
            showStatus(`✅ Found ${results.length} history entries. Download ready.`); // Show success status
        });
    });

    // Direct import button event
    directImportBtn.addEventListener("click", async () => {
        showStatus("Checking tool connection..."); // Show connection check status
        
        const connection = await checkToolConnection(); // Check tool connection
        if (!connection.connected) { // If tool not connected
            showStatus("Desktop tool not found. Please ensure the tool is running and try again, or use the file workflow.", true); // Show error
            return; // Exit function
        }
        
        showStatus("Fetching history and sending to tool..."); // Show progress status
        
        chrome.history.search({ // Search browser history
            text: "", // Empty search text
            maxResults: 500, // Maximum 500 results
            startTime: 0 // Start from beginning
        }, async (results) => {
            if (!results || results.length === 0) { // Check if no history
                showStatus("No history found."); // Show no history status
                return; // Exit function
            }
            
            // Format history for tool WITHOUT browser information
            const historyData = {
                history: results.map(item => ({
                    url: item.url, // URL
                    title: item.title || 'No Title', // Title with default
                    visitCount: item.visitCount || 1, // Visit count with default
                    lastVisitTime: item.lastVisitTime || Date.now() // Timestamp with default
                }))
            };
            
            // Send to tool
            const result = await sendHistoryToTool(historyData); // Send history to desktop tool
            
            if (result.success) { // If send successful
                showStatus(`Successfully sent ${historyData.history.length} history entries to desktop tool`); // Show success
                
                // Auto-import malicious domains if available
                setTimeout(async () => {
                    showStatus("Checking for malicious domains..."); // Show checking status
                    const domainResult = await getMaliciousDomainsFromTool(); // Get malicious domains
                    
                    if (domainResult.success && domainResult.domains.length > 0) { // If domains found
                        showStatus(`Found ${domainResult.domains.length} malicious domains. Auto-importing...`); // Show importing status
                        
                        let successCount = 0; // Initialize success counter
                        for (const domain of domainResult.domains) { // Loop through domains
                            try {
                                await blockDomain(domain); // Block each domain
                                successCount++; // Increment success counter
                                await new Promise(resolve => setTimeout(resolve, 50)); // Wait 50ms between blocks
                            } catch (error) {
                                console.error("Failed to block domain:", domain, error); // Log blocking error
                            }
                        }
                        
                        showStatus(`Auto-blocked ${successCount} malicious domains`); // Show final status
                    } else {
                        showStatus("No malicious domains found yet. Scan history in the desktop tool first."); // Show no domains status
                    }
                }, 2000); // Wait 2 seconds before checking
                
            } else {
                showStatus("Failed to send history to tool. Please use file workflow instead.", true); // Show send failure
            }
        });
    });

    // Import blocklist button
    importBtn.addEventListener("click", async () => {
        // First check if we can get domains directly from tool
        const connection = await checkToolConnection(); // Check tool connection
        if (connection.connected) { // If tool connected
            const useDirect = confirm("Desktop tool is connected. Would you like to import domains directly from the tool? Click Cancel to use file import instead.");
            
            if (useDirect) { // If user wants direct import
                showStatus("Importing domains from desktop tool..."); // Show import status
                const result = await getMaliciousDomainsFromTool(); // Get domains from tool
                
                if (result.success && result.domains.length > 0) { // If domains found
                    let successCount = 0; // Initialize success counter
                    for (const domain of result.domains) { // Loop through domains
                        try {
                            await blockDomain(domain); // Block each domain
                            successCount++; // Increment success counter
                            await new Promise(resolve => setTimeout(resolve, 50)); // Wait 50ms between blocks
                        } catch (error) {
                            console.error("Failed to block domain:", domain, error); // Log blocking error
                        }
                    }
                    showStatus(`Successfully imported and blocked ${successCount} domains from tool`); // Show success status
                } else {
                    showStatus("No malicious domains found in tool. Please scan history first.", true); // Show no domains error
                    // Fall back to file import
                    triggerFileImport(); // Trigger file import
                }
            } else {
                triggerFileImport(); // Trigger file import
            }
        } else {
            triggerFileImport(); // Trigger file import
        }
    });

    // Manage Blocklist button event
    manageBtn.addEventListener("click", showBlocklistManagement); // Show blocklist management on click

    // Load previously blocked domains
    chrome.storage.local.get({blockedDomains: {}}, (result) => {
        const blockedDomains = result.blockedDomains; // Get blocked domains from storage
        const count = Object.keys(blockedDomains).length; // Count blocked domains
        
        if (count > 0) { // If domains are blocked
            showStatus(`${count} domains already blocked. Click "Manage Blocklist" to view or remove them.`); // Show blocked count
        } else {
            showStatus("Ready to scan browsing history"); // Show ready status
        }
    });

    // Debug: Log current rules
    chrome.declarativeNetRequest.getDynamicRules((rules) => {
        console.log("Current blocking rules:", rules); // Log current blocking rules for debugging
    });
});