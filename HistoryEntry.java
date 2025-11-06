public class HistoryEntry {
    private String url;
    private String title;
    private int visitCount;
    private long lastVisitTime;
    private String browser;
    
    // Constructor with browser parameter
    public HistoryEntry(String url, String title, int visitCount, long lastVisitTime, String browser) {
        this.url = url;
        this.title = title;
        this.visitCount = visitCount;
        this.lastVisitTime = lastVisitTime;
        this.browser = browser != null ? browser : "Google Chrome";
    }
    
    // Constructor WITHOUT browser parameter
    public HistoryEntry(String url, String title, int visitCount, long lastVisitTime) {
        this(url, title, visitCount, lastVisitTime, "Google Chrome");
    }
    
    // Getters
    public String getUrl() { return url; }
    public String getTitle() { return title; }
    public int getVisitCount() { return visitCount; }
    public long getLastVisitTime() { return lastVisitTime; }
    public String getBrowser() { return browser; }
    
    // Setters
    public void setUrl(String url) { this.url = url; }
    public void setTitle(String title) { this.title = title; }
    public void setVisitCount(int visitCount) { this.visitCount = visitCount; }
    public void setLastVisitTime(long lastVisitTime) { this.lastVisitTime = lastVisitTime; }
    public void setBrowser(String browser) { this.browser = browser; }
    
    @Override
    public String toString() {
        return "HistoryEntry{url='" + url + "', title='" + title + "', visits=" + visitCount + 
               ", lastVisit=" + lastVisitTime + ", browser='" + browser + "'}";
    }
}