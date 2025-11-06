import java.io.*;
import java.sql.*;
import java.util.*;
import java.util.List;

public class HistoryParser {
    public static List<HistoryEntry> getHistory(String browser) {
        List<HistoryEntry> history = new ArrayList<>();
        String historyPath = "";
        
        try {
            // Determine browser history path
            String os = System.getProperty("os.name").toLowerCase();
            String userHome = System.getProperty("user.home");
            
            if (browser.equals("Google Chrome")) {
                if (os.contains("win")) {
                    historyPath = userHome + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History";
                } else if (os.contains("mac")) {
                    historyPath = userHome + "/Library/Application Support/Google/Chrome/Default/History";
                } else { // linux
                    historyPath = userHome + "/.config/google-chrome/Default/History";
                }
            } 
            else if (browser.equals("Brave")) {
                if (os.contains("win")) {
                    historyPath = userHome + "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History";
                } else if (os.contains("mac")) {
                    historyPath = userHome + "/Library/Application Support/BraveSoftware/Brave-Browser/Default/History";
                } else { // linux
                    historyPath = userHome + "/.config/BraveSoftware/Brave-Browser/Default/History";
                }
            }
            else if (browser.equals("Microsoft Edge")) {
                if (os.contains("win")) {
                    historyPath = userHome + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History";
                } else if (os.contains("mac")) {
                    historyPath = userHome + "/Library/Application Support/Microsoft Edge/Default/History";
                } else { // linux
                    historyPath = userHome + "/.config/microsoft-edge/Default/History";
                }
            }
            
            // Read Chrome-based history (Chrome, Brave, Edge all use same format)
            history = parseChromeBasedHistory(historyPath, browser);
            
        } catch (Exception e) {
            System.err.println("Error accessing " + browser + " history: " + e.getMessage());
        }
        
        return history;
    }
    
    public static List<HistoryEntry> parseHistoryFile(File historyFile, String browser) {
        List<HistoryEntry> history = new ArrayList<>();
        
        try {
            String fileName = historyFile.getName().toLowerCase();
            
            if (fileName.endsWith(".csv")) {
                history = parseCSVFile(historyFile, browser);
            } else if (fileName.endsWith(".sqlite") || fileName.endsWith(".db")) {
                // USE THE BROWSER PARAMETER to determine how to parse SQLite
                history = parseChromeBasedHistory(historyFile.getAbsolutePath(), browser);
            } else {
                // Try to auto-detect file type and parse
                history = tryAutoDetectFileType(historyFile, browser);
            }
            
            // Log which browser mode we're using for this import
            System.out.println("Imported history file in " + browser + " mode: " + history.size() + " entries");
            
        } catch (Exception e) {
            System.err.println("Error parsing history file: " + e.getMessage());
            throw new RuntimeException("Failed to parse history file: " + e.getMessage());
        }
        
        return history;
    }
    
    private static List<HistoryEntry> parseCSVFile(File csvFile, String browser) {
        List<HistoryEntry> history = new ArrayList<>();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(csvFile))) {
            String line;
            boolean firstLine = true;
            int urlIndex = -1;
            int titleIndex = -1;
            int visitCountIndex = -1;
            int lastVisitTimeIndex = -1;
            
            while ((line = reader.readLine()) != null) {
                // Handle CSV with quotes and commas
                String[] columns = parseCSVLine(line);
                
                // Detect column positions from header
                if (firstLine) {
                    firstLine = false;
                    for (int i = 0; i < columns.length; i++) {
                        String column = columns[i].replace("\"", "").trim().toLowerCase();
                        if (column.contains("url")) urlIndex = i;
                        if (column.contains("title") || column.contains("name")) titleIndex = i;
                        if (column.contains("visitcount")) visitCountIndex = i;
                        if (column.contains("lastvisittime")) lastVisitTimeIndex = i;
                    }
                    continue;
                }
                
                // Extract data from columns
                if (urlIndex >= 0 && urlIndex < columns.length) {
                    String url = columns[urlIndex].replace("\"", "").trim();
                    String title = (titleIndex >= 0 && titleIndex < columns.length) ? 
                        columns[titleIndex].replace("\"", "").trim() : "No Title";
                    int visitCount = (visitCountIndex >= 0 && visitCountIndex < columns.length) ? 
                        tryParseInt(columns[visitCountIndex].replace("\"", "").trim()) : 1;
                    long lastVisitTime = (lastVisitTimeIndex >= 0 && lastVisitTimeIndex < columns.length) ? 
                        tryParseLong(columns[lastVisitTimeIndex].replace("\"", "").trim()) : System.currentTimeMillis();
                    
                    if (!url.isEmpty() && url.startsWith("http")) {
                        history.add(new HistoryEntry(url, title, visitCount, lastVisitTime, browser));
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Error reading CSV file: " + e.getMessage());
        }
        
        return history;
    }
    
    private static int tryParseInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return 1;
        }
    }
    
    private static long tryParseLong(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return System.currentTimeMillis();
        }
    }
    
    private static String[] parseCSVLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder currentField = new StringBuilder();
        boolean inQuotes = false;
        
        for (char c : line.toCharArray()) {
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                fields.add(currentField.toString());
                currentField.setLength(0);
            } else {
                currentField.append(c);
            }
        }
        fields.add(currentField.toString());
        
        return fields.toArray(new String[0]);
    }
    
    private static List<HistoryEntry> tryAutoDetectFileType(File file, String browser) {
        // Try to detect file type by reading first few lines
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String firstLine = reader.readLine();
            if (firstLine != null) {
                if (firstLine.contains("url") && firstLine.contains("title") && firstLine.contains(",")) {
                    return parseCSVFile(file, browser);
                }
            }
        } catch (IOException e) {
            // Ignore and try other methods
        }
        
        // If auto-detection fails, try SQLite format
        try {
            return parseChromeBasedHistory(file.getAbsolutePath(), browser);
        } catch (Exception e) {
            throw new RuntimeException("Could not auto-detect file format. Please use CSV or SQLite format.");
        }
    }
    
    private static List<HistoryEntry> parseChromeBasedHistory(String historyPath, String browser) {
        List<HistoryEntry> history = new ArrayList<>();
        
        try {
            // Load SQLite JDBC driver
            Class.forName("org.sqlite.JDBC");
            
            // Create connection to the database
            Connection connection = DriverManager.getConnection("jdbc:sqlite:" + historyPath);
            Statement statement = connection.createStatement();
            
            // Query to get browsing history
            ResultSet resultSet = statement.executeQuery(
                "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100");
            
            while (resultSet.next()) {
                String url = resultSet.getString("url");
                String title = resultSet.getString("title");
                int visitCount = resultSet.getInt("visit_count");
                long lastVisitTime = resultSet.getLong("last_visit_time");
                
                history.add(new HistoryEntry(url, title, visitCount, lastVisitTime, browser));
            }
            
            // Clean up
            resultSet.close();
            statement.close();
            connection.close();
            
        } catch (Exception e) {
            System.err.println("Error reading Chrome-based history: " + e.getMessage());
        }
        
        return history;
    }
}