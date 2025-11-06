import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;

public class CommunicationServer {
    private static HttpServer server;
    private static boolean isRunning = false;
    private static int port = 8765;
    
    public static void startServer() {
        try {
            server = HttpServer.create(new InetSocketAddress(port), 0);
            server.createContext("/api/history", new HistoryHandler());
            server.createContext("/api/status", new StatusHandler());
            server.createContext("/api/import", new ImportHandler());
            server.createContext("/api/malicious", new MaliciousHandler());
            server.createContext("/api/analyze", new AnalyzeHandler());
            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
            isRunning = true;
            System.out.println("Communication server started on port " + port);
            System.out.println("Endpoints available:");
            System.out.println("  GET  /api/status    - Check server status");
            System.out.println("  POST /api/history   - Receive history from extension");
            System.out.println("  GET  /api/import    - Get malicious domains for extension");
            System.out.println("  GET  /api/malicious - Get current malicious URLs");
            System.out.println("  GET  /api/analyze   - Get URL analysis");
        } catch (IOException e) {
            System.err.println("Failed to start communication server: " + e.getMessage());
        }
    }
    
    public static void stopServer() {
        if (server != null) {
            server.stop(0);
            isRunning = false;
            System.out.println("Communication server stopped");
        }
    }
    
    public static boolean isRunning() {
        return isRunning;
    }
    
    public static int getPort() {
        return port;
    }
    
    static class HistoryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                handleHistoryPost(exchange);
            } else if ("GET".equals(exchange.getRequestMethod())) {
                handleHistoryGet(exchange);
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
        
        private void handleHistoryPost(HttpExchange exchange) throws IOException {
            try {
                InputStream requestBody = exchange.getRequestBody();
                String body = new String(requestBody.readAllBytes(), StandardCharsets.UTF_8);
                
                System.out.println("Received history data from extension: " + body.length() + " characters");
                
                List<HistoryEntry> entries = parseHistoryFromJSON(body);
                
                if (entries != null && !entries.isEmpty()) {
                    // Use the correct method name that exists in Main
                    Main.updateHistoryEntries(entries);
                    
                    DatabaseManager dbManager = Main.getDbManager();
                    if (dbManager != null) {
                        dbManager.saveHistoryEntries(entries);
                    }
                    
                    String response = "{\"status\": \"success\", \"message\": \"Received " + entries.size() + " history entries\", \"entries\": " + entries.size() + "}";
                    sendJsonResponse(exchange, 200, response);
                    System.out.println("✅ Processed " + entries.size() + " history entries from extension");
                } else {
                    String response = "{\"status\": \"error\", \"message\": \"No valid history data found\"}";
                    sendJsonResponse(exchange, 400, response);
                    System.out.println("❌ No valid history entries found");
                }
                
            } catch (Exception e) {
                System.err.println("❌ Error processing history data: " + e.getMessage());
                e.printStackTrace();
                String errorResponse = "{\"status\": \"error\", \"message\": \"" + escapeJson(e.getMessage()) + "\"}";
                sendJsonResponse(exchange, 500, errorResponse);
            }
        }
        
        private void handleHistoryGet(HttpExchange exchange) throws IOException {
            List<HistoryEntry> entries = Main.getCurrentHistory();
            StringBuilder jsonBuilder = new StringBuilder();
            jsonBuilder.append("{\"count\":").append(entries.size()).append(",\"entries\":[");
            
            for (int i = 0; i < entries.size(); i++) {
                HistoryEntry entry = entries.get(i);
                jsonBuilder.append("{")
                          .append("\"url\":\"").append(escapeJson(entry.getUrl())).append("\",")
                          .append("\"title\":\"").append(escapeJson(entry.getTitle())).append("\",")
                          .append("\"visitCount\":").append(entry.getVisitCount()).append(",")
                          .append("\"lastVisitTime\":").append(entry.getLastVisitTime())
                          .append("}");
                if (i < entries.size() - 1) {
                    jsonBuilder.append(",");
                }
            }
            jsonBuilder.append("]}");
            
            sendJsonResponse(exchange, 200, jsonBuilder.toString());
        }
        
        private List<HistoryEntry> parseHistoryFromJSON(String jsonData) {
            List<HistoryEntry> entries = new ArrayList<>();
            try {
                System.out.println("Parsing JSON data...");
                
                String browser = "Google Chrome";
                
                if (jsonData.trim().startsWith("{")) {
                    if (jsonData.contains("\"browser\"")) {
                        int browserStart = jsonData.indexOf("\"browser\":\"") + 11;
                        int browserEnd = jsonData.indexOf("\"", browserStart);
                        if (browserStart > 10 && browserEnd > browserStart) {
                            String detectedBrowser = jsonData.substring(browserStart, browserEnd);
                            if (detectedBrowser.equals("Google Chrome") || detectedBrowser.equals("Brave") || detectedBrowser.equals("Microsoft Edge")) {
                                browser = detectedBrowser;
                            }
                            System.out.println("Detected browser from extension: " + browser);
                        }
                    }
                    
                    if (jsonData.contains("\"history\"")) {
                        System.out.println("Detected Chrome history format with browser: " + browser);
                        int start = jsonData.indexOf("[");
                        int end = jsonData.lastIndexOf("]");
                        if (start != -1 && end != -1) {
                            String arrayContent = jsonData.substring(start + 1, end);
                            entries.addAll(parseJSONArray(arrayContent, browser));
                        }
                    } else {
                        int start = jsonData.indexOf("[");
                        int end = jsonData.lastIndexOf("]");
                        if (start != -1 && end != -1) {
                            String arrayContent = jsonData.substring(start + 1, end);
                            entries.addAll(parseJSONArray(arrayContent, browser));
                        }
                    }
                } else if (jsonData.trim().startsWith("[")) {
                    System.out.println("Detected direct array format");
                    String arrayContent = jsonData.substring(1, jsonData.length() - 1);
                    entries.addAll(parseJSONArray(arrayContent, browser));
                } else {
                    System.out.println("Trying CSV format fallback");
                    entries.addAll(parseCSVFormat(jsonData));
                }
            } catch (Exception e) {
                System.err.println("Error parsing history data: " + e.getMessage());
                entries.addAll(parseCSVFormat(jsonData));
            }
            
            System.out.println("Parsed " + entries.size() + " history entries from browser: " + (entries.isEmpty() ? "Google Chrome" : entries.get(0).getBrowser()));
            return entries;
        }
        
        private List<HistoryEntry> parseJSONArray(String arrayContent, String browser) {
            List<HistoryEntry> entries = new ArrayList<>();
            try {
                String[] objects = arrayContent.split("(?<=\\}),(?=\\{)");
                System.out.println("Found " + objects.length + " potential objects");
                
                for (String obj : objects) {
                    String cleanObj = obj.replace("{", "").replace("}", "").trim();
                    if (cleanObj.isEmpty()) continue;
                    
                    String url = extractJsonField(cleanObj, "url");
                    String title = extractJsonField(cleanObj, "title");
                    if (title.isEmpty()) title = "No Title";
                    
                    String visitCountStr = extractJsonField(cleanObj, "visitCount");
                    int visitCount = visitCountStr.isEmpty() ? 1 : tryParseInt(visitCountStr);
                    
                    String lastVisitTimeStr = extractJsonField(cleanObj, "lastVisitTime");
                    long lastVisitTime = lastVisitTimeStr.isEmpty() ? 
                        System.currentTimeMillis() : 
                        tryParseTimestamp(lastVisitTimeStr);
                    
                    if (!url.isEmpty() && (url.startsWith("http") || url.startsWith("chrome-extension"))) {
                        // Use the constructor with browser parameter
                        entries.add(new HistoryEntry(url, title, visitCount, lastVisitTime, browser));
                    }
                }
            } catch (Exception e) {
                System.err.println("Error parsing JSON array: " + e.getMessage());
                e.printStackTrace();
            }
            return entries;
        }
        
        private List<HistoryEntry> parseCSVFormat(String data) {
            List<HistoryEntry> entries = new ArrayList<>();
            try {
                String[] lines = data.split("\n");
                for (String line : lines) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("{")) continue;
                    
                    String[] parts = line.split(",", 4);
                    if (parts.length >= 1) {
                        String url = parts[0].replace("\"", "").trim();
                        String title = parts.length > 1 ? parts[1].replace("\"", "").trim() : "No Title";
                        int visitCount = parts.length > 2 ? tryParseInt(parts[2].replace("\"", "").trim()) : 1;
                        long lastVisitTime = parts.length > 3 ? 
                            tryParseTimestamp(parts[3].replace("\"", "").trim()) : 
                            System.currentTimeMillis();
                        
                        if (!url.isEmpty() && url.startsWith("http")) {
                            entries.add(new HistoryEntry(url, title, visitCount, lastVisitTime, "Google Chrome"));
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("Error parsing CSV format: " + e.getMessage());
            }
            return entries;
        }
        
        private String extractJsonField(String json, String fieldName) {
            try {
                String searchStr = "\"" + fieldName + "\":";
                int start = json.indexOf(searchStr);
                if (start == -1) return "";
                
                start += searchStr.length();
                int end = json.indexOf(",", start);
                if (end == -1) end = json.length();
                
                String value = json.substring(start, end).trim();
                if (value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                return value;
            } catch (Exception e) {
                return "";
            }
        }
        
        private int tryParseInt(String value) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                return 1;
            }
        }
        
        private long tryParseTimestamp(String value) {
            try {
                if (value.contains(".")) {
                    String[] parts = value.split("\\.");
                    return Long.parseLong(parts[0]);
                }
                return Long.parseLong(value);
            } catch (NumberFormatException e) {
                System.err.println("Warning: Invalid timestamp format: " + value + ", using current time");
                return System.currentTimeMillis();
            }
        }
    }
    
    static class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            List<HistoryEntry> historyEntries = Main.getCurrentHistory();
            List<HistoryEntry> maliciousEntries = Main.getCurrentMaliciousUrls();
            
            String response = "{\"status\":\"running\",\"port\":" + port + 
                            ",\"mainAppConnected\":true" +
                            ",\"historyCount\":" + historyEntries.size() +
                            ",\"maliciousCount\":" + maliciousEntries.size() + "}";
            
            sendJsonResponse(exchange, 200, response);
        }
    }
    
    static class ImportHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            List<HistoryEntry> maliciousUrls = Main.getCurrentMaliciousUrls();
            Set<String> domains = new LinkedHashSet<>();
            
            for (HistoryEntry entry : maliciousUrls) {
                String domain = extractDomain(entry.getUrl());
                if (domain != null && !domain.isEmpty()) {
                    domains.add(domain);
                }
            }
            
            StringBuilder response = new StringBuilder("{\"domains\":[");
            int count = 0;
            for (String domain : domains) {
                response.append("\"").append(escapeJson(domain)).append("\"");
                if (++count < domains.size()) {
                    response.append(",");
                }
            }
            response.append("],\"count\":").append(domains.size())
                   .append(",\"timestamp\":").append(System.currentTimeMillis()).append("}");
            
            sendJsonResponse(exchange, 200, response.toString());
        }
        
        private String extractDomain(String url) {
            try {
                java.net.URL urlObj = new java.net.URL(url);
                String domain = urlObj.getHost();
                if (domain.startsWith("www.")) {
                    domain = domain.substring(4);
                }
                return domain;
            } catch (Exception e) {
                return url.replace("https://", "").replace("http://", "").split("/")[0].replace("www.", "");
            }
        }
    }
    
    static class MaliciousHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            List<HistoryEntry> maliciousUrls = Main.getCurrentMaliciousUrls();
            StringBuilder jsonBuilder = new StringBuilder();
            jsonBuilder.append("{\"count\":").append(maliciousUrls.size()).append(",\"maliciousUrls\":[");
            
            for (int i = 0; i < maliciousUrls.size(); i++) {
                HistoryEntry entry = maliciousUrls.get(i);
                jsonBuilder.append("{")
                          .append("\"url\":\"").append(escapeJson(entry.getUrl())).append("\",")
                          .append("\"title\":\"").append(escapeJson(entry.getTitle())).append("\",")
                          .append("\"visitCount\":").append(entry.getVisitCount()).append(",")
                          .append("\"lastVisitTime\":").append(entry.getLastVisitTime())
                          .append("}");
                if (i < maliciousUrls.size() - 1) {
                    jsonBuilder.append(",");
                }
            }
            jsonBuilder.append("]}");
            
            sendJsonResponse(exchange, 200, jsonBuilder.toString());
        }
    }
    
    static class AnalyzeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            List<HistoryEntry> entries = Main.getCurrentHistory();
            List<URLAnalyzer.URLFrequency> frequencyAnalysis = URLAnalyzer.analyzeFrequency(entries);
            Map<String, Integer> domainAnalysis = URLAnalyzer.analyzeDomainFrequency(entries);
            List<String> topDomains = URLAnalyzer.getTopDomains(entries, 10);
            
            StringBuilder response = new StringBuilder();
            response.append("{\"analysis\":{\n");
            response.append("  \"totalEntries\":").append(entries.size()).append(",\n");
            response.append("  \"uniqueUrls\":").append(frequencyAnalysis.size()).append(",\n");
            response.append("  \"uniqueDomains\":").append(domainAnalysis.size()).append(",\n");
            response.append("  \"topDomains\":[\n");
            
            for (int i = 0; i < topDomains.size(); i++) {
                response.append("    \"").append(escapeJson(topDomains.get(i))).append("\"");
                if (i < topDomains.size() - 1) {
                    response.append(",");
                }
                response.append("\n");
            }
            response.append("  ],\n");
            response.append("  \"mostFrequentUrls\":[\n");
            
            for (int i = 0; i < Math.min(5, frequencyAnalysis.size()); i++) {
                URLAnalyzer.URLFrequency freq = frequencyAnalysis.get(i);
                response.append("    {\"url\":\"").append(escapeJson(freq.getUrl()))
                       .append("\",\"frequency\":").append(freq.getFrequency()).append("}");
                if (i < Math.min(5, frequencyAnalysis.size()) - 1) {
                    response.append(",");
                }
                response.append("\n");
            }
            response.append("  ]\n");
            response.append("}}");
            
            sendJsonResponse(exchange, 200, response.toString());
        }
    }
    
    private static void sendJsonResponse(HttpExchange exchange, int statusCode, String jsonResponse) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
        
        byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        
        OutputStream os = exchange.getResponseBody();
        os.write(responseBytes);
        os.close();
    }
    
    private static String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                 .replace("\"", "\\\"")
                 .replace("\n", "\\n")
                 .replace("\r", "\\r")
                 .replace("\t", "\\t");
    }
}