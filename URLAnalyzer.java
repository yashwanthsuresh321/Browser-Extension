import java.util.*;

public class URLAnalyzer {
    
    public static class URLFrequency {
        private String url;
        private int frequency;
        
        public URLFrequency(String url, int frequency) {
            this.url = url;
            this.frequency = frequency;
        }
        
        public String getUrl() { return url; }
        public int getFrequency() { return frequency; }
        
        @Override
        public String toString() {
            return url + " (visited " + frequency + " times)";
        }
    }
    
    public static List<URLFrequency> analyzeFrequency(List<HistoryEntry> entries) {
        Map<String, Integer> frequencyMap = new HashMap<>();
        
        for (HistoryEntry entry : entries) {
            String url = entry.getUrl();
            frequencyMap.put(url, frequencyMap.getOrDefault(url, 0) + 1);
        }
        
        List<URLFrequency> result = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : frequencyMap.entrySet()) {
            result.add(new URLFrequency(entry.getKey(), entry.getValue()));
        }
        
        // Sort by frequency descending
        result.sort((a, b) -> Integer.compare(b.getFrequency(), a.getFrequency()));
        return result;
    }
    
    public static Map<String, Integer> analyzeDomainFrequency(List<HistoryEntry> entries) {
        Map<String, Integer> domainFrequency = new HashMap<>();
        
        for (HistoryEntry entry : entries) {
            String domain = extractDomain(entry.getUrl());
            if (domain != null && !domain.isEmpty()) {
                domainFrequency.put(domain, domainFrequency.getOrDefault(domain, 0) + 1);
            }
        }
        
        return domainFrequency;
    }
    
    public static List<String> getTopDomains(List<HistoryEntry> entries, int topN) {
        Map<String, Integer> domainFrequency = analyzeDomainFrequency(entries);
        
        List<Map.Entry<String, Integer>> sortedDomains = new ArrayList<>(domainFrequency.entrySet());
        sortedDomains.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
        
        List<String> topDomains = new ArrayList<>();
        for (int i = 0; i < Math.min(topN, sortedDomains.size()); i++) {
            topDomains.add(sortedDomains.get(i).getKey() + " (" + sortedDomains.get(i).getValue() + " visits)");
        }
        
        return topDomains;
    }
    
    public static List<HistoryEntry> filterByDomain(List<HistoryEntry> entries, String domain) {
        List<HistoryEntry> filtered = new ArrayList<>();
        for (HistoryEntry entry : entries) {
            if (extractDomain(entry.getUrl()).equals(domain)) {
                filtered.add(entry);
            }
        }
        return filtered;
    }
    
    public static List<HistoryEntry> getRecentVisits(List<HistoryEntry> entries, int days) {
        List<HistoryEntry> recent = new ArrayList<>();
        long cutoffTime = System.currentTimeMillis() - (days * 24L * 60 * 60 * 1000);
        
        for (HistoryEntry entry : entries) {
            if (entry.getLastVisitTime() >= cutoffTime) {
                recent.add(entry);
            }
        }
        
        // Sort by most recent first
        recent.sort((a, b) -> Long.compare(b.getLastVisitTime(), a.getLastVisitTime()));
        return recent;
    }
    
    private static String extractDomain(String url) {
        try {
            java.net.URL urlObj = new java.net.URL(url);
            String domain = urlObj.getHost();
            if (domain.startsWith("www.")) {
                domain = domain.substring(4);
            }
            return domain;
        } catch (Exception e) {
            String cleanUrl = url.replace("https://", "").replace("http://", "");
            int slashIndex = cleanUrl.indexOf('/');
            if (slashIndex > 0) {
                cleanUrl = cleanUrl.substring(0, slashIndex);
            }
            if (cleanUrl.startsWith("www.")) {
                cleanUrl = cleanUrl.substring(4);
            }
            return cleanUrl;
        }
    }
}