// Import necessary Java packages for database operations and data structures
import java.sql.*; // For JDBC database connectivity (Connection, Statement, PreparedStatement, ResultSet, SQLException)
import java.util.ArrayList; // For dynamic arrays
import java.util.List; // For List interface

// Main class responsible for managing database operations
public class DatabaseManager {
    private Connection connection; // Database connection object - maintains link to SQLite database
    
    // Constructor - automatically initializes database when object is created
    public DatabaseManager() {
        initializeDatabase(); // Call database setup method
    }
    
    // Method to set up database connection and create required tables
    public void initializeDatabase() {
        try {
            // Try to load SQLite driver - essential for JDBC to work with SQLite
            try {
                Class.forName("org.sqlite.JDBC"); // Load SQLite JDBC driver class
                System.out.println("SQLite JDBC driver loaded successfully"); // Success confirmation
            } catch (ClassNotFoundException e) {
                // Handle case where SQLite driver is not available in classpath
                System.err.println("❌ SQLite JDBC driver not found. Running in memory-only mode.");
                System.err.println("💡 Download sqlite-jdbc.jar and place it in the same directory");
                return; // Exit method early since database functionality won't work
            }
            
            // Try to connect to database file
            try {
                // Create connection to SQLite database file (will be created if doesn't exist)
                connection = DriverManager.getConnection("jdbc:sqlite:history_analyzer.db");
                System.out.println("✅ Database connected: history_analyzer.db"); // Connection success message
            } catch (SQLException e) {
                // Handle database connection failures
                System.err.println("❌ Database connection failed: " + e.getMessage());
                System.err.println("💡 Running in memory-only mode");
                return; // Exit method - database operations will be skipped
            }
            
            // Create tables if they don't exist
            // SQL for history_entries table - stores browsing history data
            String createHistoryTable = "CREATE TABLE IF NOT EXISTS history_entries (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " + // Auto-incrementing primary key
                "url TEXT NOT NULL, " + // Website URL (required field)
                "title TEXT, " + // Page title (optional)
                "visit_count INTEGER, " + // Number of times visited
                "last_visit_time INTEGER, " + // Timestamp of last visit
                "import_time DATETIME DEFAULT CURRENT_TIMESTAMP, " + // When record was imported
                "UNIQUE(url, last_visit_time))"; // Prevent duplicate URL+timestamp combinations
                
            // SQL for malicious_urls table - stores detected malicious websites PERMANENTLY
            String createMaliciousTable = "CREATE TABLE IF NOT EXISTS malicious_urls (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " + // Auto-incrementing primary key
                "url TEXT NOT NULL UNIQUE, " + // Malicious website URL with UNIQUE constraint
                "domain TEXT, " + // NEW: Store the domain name for easy reporting
                "title TEXT, " + // Page title
                "positives INTEGER, " + // Number of security vendors that flagged as malicious
                "total INTEGER, " + // Total number of vendors scanned
                "visit_count INTEGER, " + // How many times user visited this URL
                "last_visit_time INTEGER, " + // When user last visited
                "session_id INTEGER, " + // NEW: Link to analysis_sessions table
                "detection_time DATETIME DEFAULT (datetime('now', 'localtime')), " + // FIXED: Use localtime
                "scan_date DATETIME DEFAULT (datetime('now', 'localtime')), " + // FIXED: Use localtime
                "FOREIGN KEY (session_id) REFERENCES analysis_sessions(id), " + // NEW: Foreign key constraint
                "UNIQUE(url))"; // Each URL should appear only once in this table
                
            // SQL for settings table - stores application configuration
            String createSettingsTable = "CREATE TABLE IF NOT EXISTS settings (" +
                "key TEXT PRIMARY KEY, " + // Setting name (e.g., 'api_key')
                "value TEXT)"; // Setting value (e.g., actual API key)
                
            // SQL for analysis_sessions table - stores scan session summaries
            String createAnalysisTable = "CREATE TABLE IF NOT EXISTS analysis_sessions (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " + // Auto-incrementing primary key
                "session_date DATETIME DEFAULT (datetime('now', 'localtime')), " + // FIXED: Use localtime
                "total_urls INTEGER, " + // Total URLs scanned in this session
                "malicious_count INTEGER, " + // Number of malicious URLs found
                "scan_duration INTEGER, " + // How long the scan took (milliseconds)
                "malicious_domains TEXT)"; // NEW: Store comma-separated list of malicious domains found
            
            // Execute all table creation SQL statements
            Statement stmt = connection.createStatement(); // Create SQL statement object
            stmt.execute(createHistoryTable); // Create history_entries table
            stmt.execute(createMaliciousTable); // Create malicious_urls table
            stmt.execute(createSettingsTable); // Create settings table
            stmt.execute(createAnalysisTable); // Create analysis_sessions table
            
            // FIX: Add missing columns if they don't exist
            try {
                stmt.execute("ALTER TABLE malicious_urls ADD COLUMN domain TEXT");
                System.out.println("✅ Added missing domain column to malicious_urls table");
            } catch (SQLException e) {
                // Column already exists, this is fine - just log it
                System.out.println("ℹ️ domain column already exists in malicious_urls table");
            }
            
            try {
                stmt.execute("ALTER TABLE malicious_urls ADD COLUMN session_id INTEGER");
                System.out.println("✅ Added missing session_id column to malicious_urls table");
            } catch (SQLException e) {
                // Column already exists, this is fine - just log it
                System.out.println("ℹ️ session_id column already exists in malicious_urls table");
            }
            
            try {
                stmt.execute("ALTER TABLE analysis_sessions ADD COLUMN malicious_domains TEXT");
                System.out.println("✅ Added missing malicious_domains column to analysis_sessions table");
            } catch (SQLException e) {
                // Column already exists, this is fine - just log it
                System.out.println("ℹ️ malicious_domains column already exists in analysis_sessions table");
            }
            
            stmt.close(); // Close statement to release database resources
            
            System.out.println("✅ Database tables initialized successfully"); // Table creation success
            
        } catch (Exception e) {
            // Catch any unexpected errors during database initialization
            System.err.println("❌ Database initialization error: " + e.getMessage());
            e.printStackTrace();
            System.err.println("💡 Application will run without database persistence");
        }
    }
    
    /**
     * IMPROVED: Save malicious URL to PERMANENT storage with session linking and domain extraction
     * @param entry The history entry containing URL and metadata
     * @param positives Number of positive detections from VirusTotal
     * @param total Total number of scans from VirusTotal
     * @param sessionId The analysis session ID this URL belongs to
     * @return true if successfully saved, false otherwise
     */
    public boolean saveMaliciousUrl(HistoryEntry entry, int positives, int total, int sessionId) {
        if (!isDatabaseAvailable() || entry == null) {
            System.out.println("💡 Database not available or null entry - skipping saveMaliciousUrl");
            return false; // Return failure if no database or invalid entry
        }
        
        try {
            // Extract domain from URL
            String domain = extractDomain(entry.getUrl());
            
            // Use INSERT OR REPLACE to update if URL already exists (prevents duplicates)
            String sql = "INSERT OR REPLACE INTO malicious_urls (url, domain, title, positives, total, visit_count, last_visit_time, session_id, scan_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))";
            PreparedStatement preparedStatement = connection.prepareStatement(sql); // Create prepared statement
            preparedStatement.setString(1, entry.getUrl()); // Set URL parameter
            preparedStatement.setString(2, domain); // Set domain parameter
            preparedStatement.setString(3, entry.getTitle()); // Set title parameter
            preparedStatement.setInt(4, positives); // Set number of positive detections
            preparedStatement.setInt(5, total); // Set total number of vendors
            preparedStatement.setInt(6, entry.getVisitCount()); // Set visit count
            preparedStatement.setLong(7, entry.getLastVisitTime()); // Set last visit time
            preparedStatement.setInt(8, sessionId); // Set session ID
            
            int rowsAffected = preparedStatement.executeUpdate(); // Execute the insert/update and get affected rows
            preparedStatement.close(); // Close statement
            
            if (rowsAffected > 0) {
                // Successfully saved to permanent storage
                System.out.println("✅ PERMANENTLY saved malicious URL to database: " + domain + " (" + positives + "/" + total + " detections)");
                return true; // Return success
            } else {
                // Failed to save
                System.out.println("❌ Failed to save malicious URL: " + entry.getUrl());
                return false; // Return failure
            }
            
        } catch (SQLException e) {
            // Handle SQL errors during malicious URL saving
            System.err.println("❌ Error saving malicious URL '" + entry.getUrl() + "': " + e.getMessage());
            e.printStackTrace(); // Print stack trace for debugging
            return false; // Return failure
        }
    }
    
    /**
     * IMPROVED: Save analysis session with malicious domains list
     * @param totalUrls Total URLs scanned
     * @param maliciousCount Number of malicious URLs found  
     * @param duration Scan duration in seconds
     * @param maliciousDomains List of malicious domains found (can be null)
     * @return The session ID of the created session
     */
    public int saveAnalysisSession(int totalUrls, int maliciousCount, long duration, List<String> maliciousDomains) {
        if (!isDatabaseAvailable()) {
            System.out.println("💡 Database not available - skipping analysis session save");
            return -1; // Return -1 if no database connection
        }
        
        try {
            // Build malicious domains string
            String domainsString = null;
            if (maliciousDomains != null && !maliciousDomains.isEmpty()) {
                domainsString = String.join(", ", maliciousDomains);
            }
            
            // SQL to insert analysis session record and return the generated ID
            String sql = "INSERT INTO analysis_sessions (total_urls, malicious_count, scan_duration, malicious_domains) VALUES (?, ?, ?, ?)";
            PreparedStatement preparedStatement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            preparedStatement.setInt(1, totalUrls); // Set total URLs scanned
            preparedStatement.setInt(2, maliciousCount); // Set number of malicious URLs found
            preparedStatement.setLong(3, duration); // Set scan duration in milliseconds
            preparedStatement.setString(4, domainsString); // Set malicious domains list
            preparedStatement.executeUpdate(); // Execute insert
            
            // Get the generated session ID
            ResultSet generatedKeys = preparedStatement.getGeneratedKeys();
            int sessionId = -1;
            if (generatedKeys.next()) {
                sessionId = generatedKeys.getInt(1);
            }
            
            preparedStatement.close(); // Close statement
            
            System.out.println("✅ Saved analysis session to database with ID: " + sessionId); // Success confirmation
            return sessionId; // Return the session ID
            
        } catch (SQLException e) {
            // Handle SQL errors during analysis session saving
            System.err.println("❌ Error saving analysis session: " + e.getMessage());
            e.printStackTrace(); // Print stack trace for debugging
            return -1; // Return -1 on error
        }
    }
    
    /**
     * Helper method to extract domain from URL
     */
    private String extractDomain(String url) {
        try {
            java.net.URL urlObj = new java.net.URL(url);
            String domain = urlObj.getHost();
            if (domain.startsWith("www.")) {
                domain = domain.substring(4);
            }
            return domain;
        } catch (Exception e) {
            // Fallback extraction
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
    
    /**
     * Get malicious URLs for a specific session
     * @param sessionId The session ID to get URLs for
     * @return List of malicious URLs from that session
     */
    public List<HistoryEntry> getMaliciousUrlsForSession(int sessionId) {
        List<HistoryEntry> entries = new ArrayList<>();
        if (!isDatabaseAvailable()) {
            return entries;
        }
        
        try {
            String sql = "SELECT url, title, domain, positives, total FROM malicious_urls WHERE session_id = ? ORDER BY scan_date DESC";
            PreparedStatement preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setInt(1, sessionId);
            ResultSet rs = preparedStatement.executeQuery();
            
            while (rs.next()) {
                HistoryEntry entry = new HistoryEntry(
                    rs.getString("url"),
                    rs.getString("title"),
                    0, // visit_count not needed
                    0  // last_visit_time not needed
                );
                entries.add(entry);
            }
            
            rs.close();
            preparedStatement.close();
            
        } catch (SQLException e) {
            System.err.println("❌ Error getting malicious URLs for session: " + e.getMessage());
        }
        return entries;
    }
    
    // PUBLIC GETTER FOR CONNECTION - FIXES THE VISIBILITY ISSUE
    public Connection getConnection() {
        return connection;
    }
    
    // Helper method to check if database connection is available
    private boolean isDatabaseAvailable() {
        return connection != null; // Returns true if connection object exists
    }
    
    /**
     * Clears ALL data from all tables
     * WARNING: This permanently deletes all stored data except settings
     */
    public void clearAllData() {
        if (!isDatabaseAvailable()) {
            System.out.println("💡 Database not available - cannot clear data"); // No database connection
            return; // Exit if no database connection
        }
        
        try {
            Statement stmt = connection.createStatement(); // Create SQL statement object
            stmt.execute("DELETE FROM history_entries"); // Delete all history entries
            stmt.execute("DELETE FROM malicious_urls"); // Delete all malicious URL records
            stmt.execute("DELETE FROM analysis_sessions"); // Delete all analysis session records
            // Don't delete API key from settings - preserve user configuration
            stmt.close(); // Close statement
            
            System.out.println("✅ All database data cleared successfully"); // Confirmation message
            
        } catch (SQLException e) {
            // Handle SQL errors during data deletion
            System.err.println("❌ Error clearing database data: " + e.getMessage());
            throw new RuntimeException("Failed to clear database data", e); // Convert to unchecked exception
        }
    }
    
    // Save history entries to database
    public void saveHistoryEntries(List<HistoryEntry> entries) {
        // Check if database is available or if entries list is empty/null
        if (!isDatabaseAvailable() || entries == null || entries.isEmpty()) {
            System.out.println("💡 Database not available or no entries - skipping saveHistoryEntries");
            return; // Exit if no database or no data to save
        }
        
        try {
            // SQL with INSERT OR IGNORE to avoid duplicates (uses UNIQUE constraint)
            String sql = "INSERT OR IGNORE INTO history_entries (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)";
            PreparedStatement preparedStatement = connection.prepareStatement(sql); // Create prepared statement for efficiency
            int batchCount = 0; // Counter for batch operations
            
            // Loop through all history entries and add to batch
            for (HistoryEntry entry : entries) {
                preparedStatement.setString(1, entry.getUrl()); // Set URL parameter
                preparedStatement.setString(2, entry.getTitle()); // Set title parameter
                preparedStatement.setInt(3, entry.getVisitCount()); // Set visit count parameter
                preparedStatement.setLong(4, entry.getLastVisitTime()); // Set last visit timestamp parameter
                preparedStatement.addBatch(); // Add this set of parameters to batch
                batchCount++; // Increment counter
                
                // Execute batch every 100 entries to manage memory
                if (batchCount % 100 == 0) {
                    preparedStatement.executeBatch(); // Execute accumulated batch
                }
            }
            
            preparedStatement.executeBatch(); // Execute any remaining entries in batch
            preparedStatement.close(); // Close prepared statement
            
            System.out.println("✅ Saved " + batchCount + " history entries to database"); // Success message
            
        } catch (SQLException e) {
            // Handle SQL errors during history saving
            System.err.println("❌ Error saving history entries: " + e.getMessage());
            e.printStackTrace(); // Print stack trace for debugging
        }
    }
    
    // Save API key to settings table for persistence between application runs
    public void saveApiKey(String apiKey) {
        if (!isDatabaseAvailable()) {
            System.out.println("💡 Database not available - API key saved in memory only");
            return; // Exit if no database connection
        }
        
        try {
            // INSERT OR REPLACE ensures only one API key exists (updates if already present)
            String sql = "INSERT OR REPLACE INTO settings (key, value) VALUES ('api_key', ?)";
            PreparedStatement preparedStatement = connection.prepareStatement(sql); // Create prepared statement
            preparedStatement.setString(1, apiKey); // Set API key parameter
            preparedStatement.executeUpdate(); // Execute insert/update
            preparedStatement.close(); // Close statement
            
            System.out.println("✅ API key saved to database"); // Success message
            
        } catch (SQLException e) {
            // Handle SQL errors during API key saving
            System.err.println("❌ Error saving API key: " + e.getMessage());
            e.printStackTrace(); // Print stack trace for debugging
        }
    }
    
    // Retrieve API key from settings table
    public String getApiKey() {
        if (!isDatabaseAvailable()) {
            System.out.println("💡 Database not available - returning empty API key");
            return ""; // Return empty string if no database
        }
        
        try {
            String sql = "SELECT value FROM settings WHERE key = 'api_key'"; // Query for API key
            Statement stmt = connection.createStatement(); // Create statement
            ResultSet rs = stmt.executeQuery(sql); // Execute query and get result set
            
            // Check if result set has data
            if (rs.next()) {
                String apiKey = rs.getString("value"); // Extract API key from result set
                rs.close(); // Close result set
                stmt.close(); // Close statement
                return apiKey; // Return found API key
            }
            
            // Clean up resources if no API key found
            rs.close(); // Close result set
            stmt.close(); // Close statement
            
        } catch (SQLException e) {
            // Handle SQL errors during API key retrieval
            System.err.println("❌ Error getting API key: " + e.getMessage());
            e.printStackTrace(); // Print stack trace for debugging
        }
        return ""; // Return empty string if no API key found or error occurred
    }
    
    // Retrieve all history entries from database, ordered by most recent visit
    public List<HistoryEntry> getHistoryEntries() {
        List<HistoryEntry> entries = new ArrayList<>(); // Create empty list for results
        if (!isDatabaseAvailable()) {
            System.out.println("💡 Database not available - returning empty history");
            return entries; // Return empty list if no database
        }
        
        try {
            // SQL query to get all history entries sorted by most recent
            String sql = "SELECT url, title, visit_count, last_visit_time FROM history_entries ORDER BY last_visit_time DESC";
            Statement stmt = connection.createStatement(); // Create statement
            ResultSet rs = stmt.executeQuery(sql); // Execute query
            
            // Process each row in result set
            while (rs.next()) {
                // Create HistoryEntry object from database columns
                HistoryEntry entry = new HistoryEntry(
                    rs.getString("url"), // Get URL
                    rs.getString("title"), // Get title
                    rs.getInt("visit_count"), // Get visit count
                    rs.getLong("last_visit_time") // Get last visit timestamp
                );
                entries.add(entry); // Add to results list
            }
            
            // Clean up database resources
            rs.close(); // Close result set
            stmt.close(); // Close statement
            
            System.out.println("✅ Retrieved " + entries.size() + " history entries from database"); // Success message
            
        } catch (SQLException e) {
            // Handle SQL errors during history retrieval
            System.err.println("❌ Error getting history entries: " + e.getMessage());
            e.printStackTrace(); // Print stack trace for debugging
        }
        return entries; // Return populated list (empty if error occurred)
    }
    
    // Retrieve all malicious URLs detected in previous scans (uses improved version)
    public List<HistoryEntry> getMaliciousUrls() {
        return getMaliciousUrlsWithDetails(); // Use the improved version with full details
    }
    
    /**
     * NEW: Get malicious URLs with full details including scan results
     * @return List of HistoryEntry objects representing malicious URLs
     */
    public List<HistoryEntry> getMaliciousUrlsWithDetails() {
        List<HistoryEntry> entries = new ArrayList<>(); // Create empty list for results
        if (!isDatabaseAvailable()) {
            System.out.println("💡 Database not available - returning empty malicious URLs");
            return entries; // Return empty list if no database
        }
        
        try {
            // SQL to get all malicious URLs with full details, ordered by most recent
            String sql = "SELECT url, title, visit_count, last_visit_time, positives, total, scan_date FROM malicious_urls ORDER BY scan_date DESC";
            Statement stmt = connection.createStatement(); // Create statement
            ResultSet rs = stmt.executeQuery(sql); // Execute query
            
            // Process each row in result set
            while (rs.next()) {
                // Create HistoryEntry object from database columns
                HistoryEntry entry = new HistoryEntry(
                    rs.getString("url"), // Get URL
                    rs.getString("title"), // Get title
                    rs.getInt("visit_count"), // Get visit count
                    rs.getLong("last_visit_time") // Get last visit timestamp
                );
                entries.add(entry); // Add to results list
            }
            
            // Clean up database resources
            rs.close(); // Close result set
            stmt.close(); // Close statement
            
            System.out.println("✅ Retrieved " + entries.size() + " malicious URLs from PERMANENT storage");
            
        } catch (SQLException e) {
            // Handle SQL errors during malicious URLs retrieval
            System.err.println("❌ Error getting malicious URLs: " + e.getMessage());
            e.printStackTrace(); // Print stack trace for debugging
        }
        return entries; // Return populated list (empty if error occurred)
    }
    
    // NEW METHOD: Check if database is actually working by testing a simple query
    public boolean testDatabaseConnection() {
        if (!isDatabaseAvailable()) {
            System.out.println("❌ Database connection is null");
            return false; // Return false if no connection
        }
        
        try {
            // Try a simple query to test the connection
            Statement stmt = connection.createStatement(); // Create statement
            ResultSet rs = stmt.executeQuery("SELECT 1 as test"); // Execute simple test query
            boolean result = rs.next(); // Check if we got a result
            rs.close(); // Close result set
            stmt.close(); // Close statement
            
            System.out.println("✅ Database connection test passed"); // Success message
            return result; // Return test result
            
        } catch (SQLException e) {
            System.err.println("❌ Database connection test failed: " + e.getMessage());
            e.printStackTrace(); // Print stack trace for debugging
            return false; // Return false on error
        }
    }
    
    // Clean up method to close database connection when done
    public void close() {
        try {
            // Check if connection exists and is still open
            if (connection != null && !connection.isClosed()) {
                connection.close(); // Close database connection
                System.out.println("✅ Database connection closed"); // Success message
            }
        } catch (SQLException e) {
            // Handle errors during connection closing
            System.err.println("❌ Error closing database connection: " + e.getMessage());
            e.printStackTrace(); // Print stack trace for debugging
        }
    }
}