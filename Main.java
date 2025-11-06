import javax.swing.*; // For GUI components (windows, buttons, text areas, etc.)
import javax.swing.filechooser.FileNameExtensionFilter; // For file type filtering in file dialogs
import java.awt.*; // For layout managers and basic UI components
import java.awt.event.WindowAdapter; // For window event handling
import java.awt.event.WindowEvent; // For window events like closing
import java.io.*; // For file input/output operations
import java.net.HttpURLConnection; // For HTTP connections to VirusTotal API
import java.net.URL; // For URL handling
import java.net.URLEncoder; // For URL encoding parameters
import java.util.*; // For collections and utility classes
import java.util.List; // For List interface
import java.util.concurrent.ExecutorService; // For thread pool management
import java.util.concurrent.Executors; // For creating thread pools
import java.util.concurrent.TimeUnit; // For time unit specifications
import java.sql.*;

// INHERITANCE: Base class for all scan results - provides common interface
abstract class ScanResult {
    protected boolean isMalicious; // Whether the URL is malicious
    protected String error; // Error message if scan failed
    
    // ENCAPSULATION: Protected fields with public getters
    public boolean isMalicious() { return isMalicious; } // Getter for malicious status
    public String getError() { return error; } // Getter for error message
    
    // POLYMORPHISM: Abstract method to be implemented by subclasses
    public abstract boolean hasValidResults(); // Check if results are valid
}

// INHERITANCE: VirusTotal-specific implementation extending ScanResult
class VTScanResult extends ScanResult {
    private int positives; // Number of positive detections
    private int total; // Total number of scans performed
    
    public VTScanResult() {
        this.isMalicious = false; // Initialize as not malicious
        this.error = null; // Initialize with no error
    }
    
    // ENCAPSULATION: Private fields with public getters
    public int getPositives() { return positives; } // Get positive detections count
    public int getTotal() { return total; } // Get total scans count
    
    public void setScanResults(int positives, int total) {
        this.positives = positives; // Set positive detections
        this.total = total; // Set total scans
        this.isMalicious = positives > 0; // Mark as malicious if any positive detections
    }
    
    public void setError(String error) {
        this.error = error; // Set error message
    }
    
    // POLYMORPHISM: Concrete implementation of abstract method
    @Override
    public boolean hasValidResults() {
        return error == null && total > 0; // Valid if no error and scans were performed
    }
}

public class Main {
    // Professional dark color scheme for modern UI
    private static final Color BACKGROUND_COLOR = new Color(13, 17, 23); // Dark background
    private static final Color CARD_COLOR = new Color(22, 27, 34); // Card background
    private static final Color ACCENT_COLOR = new Color(47, 129, 247); // Primary accent color
    private static final Color SUCCESS_COLOR = new Color(46, 160, 67); // Success indicators
    private static final Color WARNING_COLOR = new Color(219, 171, 9); // Warning indicators
    private static final Color ERROR_COLOR = new Color(248, 81, 73); // Error indicators
    private static final Color TEXT_COLOR = new Color(248, 250, 252); // Primary text color
    private static final Color LIGHT_TEXT_COLOR = new Color(139, 148, 158); // Secondary text color
    private static final Color BORDER_COLOR = new Color(48, 54, 61); // Border color
    private static final Color BUTTON_HOVER = new Color(65, 140, 255); // Button hover color
    
    // ENCAPSULATION: Constants are private and static final for data protection
    private static final int MAX_URLS_TO_SCAN = 4; // Maximum URLs to scan per minute (VirusTotal free tier limit)
    private static final int VT_RATE_LIMIT_DELAY = 16000; // Delay between API requests in milliseconds
    private static String API_KEY = ""; // VirusTotal API key (user-provided)
    private static final String VT_API_URL = "https://www.virustotal.com/vtapi/v2/url/report"; // VirusTotal API endpoint

    // ENCAPSULATION: UI components are private to control access
    private static JFrame frame; // Main application window
    private static JTextArea outputArea; // Text area for displaying scan results
    private static JProgressBar progressBar; // Progress bar for scan progress
    private static JLabel statusLabel; // Status label for current operation
    private static JTextField apiKeyField; // Text field for API key input
    private static JPanel mainPanel; // Main content panel
    
    // ENCAPSULATION: Data collections are private and thread-safe
    private static List<HistoryEntry> maliciousUrls = Collections.synchronizedList(new ArrayList<>()); // Thread-safe list for malicious URLs
    private static List<HistoryEntry> allHistoryEntries = new ArrayList<>(); // List for all history entries
    
    // Database manager for persistent storage
    private static DatabaseManager dbManager; // Handles all database operations
    
    // Concurrency management
    private static ExecutorService executorService; // Thread pool for background tasks
    
    // Rate limiting mechanism - ENCAPSULATION of timing logic
    private static long lastRequestTime = 0; // Timestamp of last API request
    private static final Object rateLimitLock = new Object(); // Lock for thread-safe rate limiting
    private static int requestCount = 0; // Counter for requests in current minute
    private static final int MAX_REQUESTS_PER_MINUTE = 4; // Maximum requests per minute
    private static long minuteStartTime = 0; // Start time of current minute window
    
    /**
     * MAIN METHOD - Application entry point
     * OOP CONCEPT: Abstraction - hides Swing thread complexity
     */
    public static void main(String[] args) {
        dbManager = new DatabaseManager(); // Initialize database manager
        try {
            dbManager.initializeDatabase(); // Set up database tables and connection
        } catch (Exception e) {
            System.err.println("Database initialization warning: " + e.getMessage()); // Log warning
            System.err.println("Continuing without database functionality..."); // Inform user
        }
        
        // Load saved API key if exists
        API_KEY = dbManager.getApiKey(); // Retrieve API key from database
        
        // NEW: Load previously detected malicious URLs from PERMANENT storage
        loadMaliciousUrlsFromDatabase(); // Load malicious URLs on startup
        
        // Start communication server for extension
        CommunicationServer.startServer(); // Start HTTP server for browser extension communication
        
        // Set dark look and feel
        setDarkLookAndFeel(); // Apply dark theme to UI components
        
        // Swing utilities ensure thread-safe GUI operations
        javax.swing.SwingUtilities.invokeLater(() -> createAndShowGUI()); // Create GUI on Event Dispatch Thread
    }
    
    /**
     * NEW: Loads malicious URLs from PERMANENT database storage on startup
     */
    private static void loadMaliciousUrlsFromDatabase() {
        if (dbManager == null) return; // Exit if no database manager available
        
        List<HistoryEntry> savedMalicious = dbManager.getMaliciousUrls(); // Get malicious URLs from database
        if (!savedMalicious.isEmpty()) {
            maliciousUrls.clear(); // Clear current memory list
            maliciousUrls.addAll(savedMalicious); // Add all database entries to memory
            if (outputArea != null) {
                outputArea.append("🔍 Loaded " + savedMalicious.size() + " previously detected malicious URLs from PERMANENT database storage.\n"); // Inform user
            }
            
            // Print database statistics
            printMaliciousStats(); // FIXED: Call local method instead of DatabaseManager method
        }
    }
    
    /**
     * NEW: Print malicious URL statistics
     */
    private static void printMaliciousStats() {
        if (dbManager == null) {
            System.out.println("💡 Database not available - cannot get stats");
            return;
        }
        
        try {
            List<HistoryEntry> maliciousEntries = dbManager.getMaliciousUrls();
            System.out.println("📊 MALICIOUS URL STATS:");
            System.out.println("   Total malicious URLs: " + maliciousEntries.size());
            
            // Get unique domains
            Set<String> domains = new HashSet<>();
            for (HistoryEntry entry : maliciousEntries) {
                String domain = extractDomain(entry.getUrl());
                domains.add(domain);
            }
            System.out.println("   Unique malicious domains: " + domains.size());
            
        } catch (Exception e) {
            System.err.println("❌ Error getting malicious stats: " + e.getMessage());
        }
    }
    
    /**
     * Loads history from database on startup
     */
    private static void loadHistoryFromDatabase() {
        if (dbManager == null) return; // Exit if no database manager available
        
        List<HistoryEntry> savedEntries = dbManager.getHistoryEntries(); // Get history entries from database
        if (!savedEntries.isEmpty()) {
            allHistoryEntries = savedEntries; // Replace memory list with database entries
            if (outputArea != null) {
                outputArea.append("📚 Loaded " + savedEntries.size() + " history entries from database.\n"); // Inform user
            }
        }
        
        // Malicious URLs are now loaded separately in loadMaliciousUrlsFromDatabase()
    }
    
    /**
     * Sets dark look and feel for the application
     */
    private static void setDarkLookAndFeel() {
        try {
            // Set dark theme colors for various UI components
            UIManager.put("Panel.background", BACKGROUND_COLOR); // Main panel background
            UIManager.put("TextArea.background", CARD_COLOR); // Text area background
            UIManager.put("TextArea.foreground", TEXT_COLOR); // Text area text color
            UIManager.put("TextArea.caretForeground", TEXT_COLOR); // Text area cursor color
            UIManager.put("TextField.background", new Color(30, 35, 42)); // Text field background
            UIManager.put("TextField.foreground", TEXT_COLOR); // Text field text color
            UIManager.put("TextField.caretForeground", TEXT_COLOR); // Text field cursor color
            UIManager.put("ComboBox.background", new Color(30, 35, 42)); // Combo box background
            UIManager.put("ComboBox.foreground", TEXT_COLOR); // Combo box text color
            UIManager.put("ComboBox.selectionBackground", ACCENT_COLOR); // Combo box selection background
            UIManager.put("ComboBox.selectionForeground", Color.WHITE); // Combo box selection text color
            UIManager.put("Button.background", ACCENT_COLOR); // Button background
            UIManager.put("Button.foreground", Color.WHITE); // Button text color
            UIManager.put("ProgressBar.background", BORDER_COLOR); // Progress bar background
            UIManager.put("ProgressBar.foreground", SUCCESS_COLOR); // Progress bar fill color
            UIManager.put("ProgressBar.selectionBackground", TEXT_COLOR); // Progress bar text background
            UIManager.put("ProgressBar.selectionForeground", TEXT_COLOR); // Progress bar text color
            UIManager.put("Label.foreground", TEXT_COLOR); // Label text color
            UIManager.put("TitledBorder.titleColor", LIGHT_TEXT_COLOR); // Titled border text color
        } catch (Exception e) {
            System.err.println("Error setting dark theme: " + e.getMessage()); // Log theme error
        }
    }
    
    /**
     * Creates a modern button with consistent styling
     * @param text The button text to display
     * @return A styled JButton instance
     */
    private static JButton createModernButton(String text) {
        JButton button = new JButton(text); // Create new button with text
        button.setBackground(ACCENT_COLOR); // Set background color
        button.setForeground(Color.WHITE); // Set text color
        button.setFocusPainted(false); // Remove focus border
        button.setBorder(BorderFactory.createCompoundBorder( // Create compound border
            BorderFactory.createLineBorder(ACCENT_COLOR.darker(), 1), // Outer border
            BorderFactory.createEmptyBorder(12, 24, 12, 24) // Inner padding
        ));
        button.setFont(new Font("Segoe UI", Font.BOLD, 13)); // Set font
        button.setCursor(new Cursor(Cursor.HAND_CURSOR)); // Set hand cursor on hover
        
        // Rounded corners effect
        button.setOpaque(true); // Make button opaque
        button.setContentAreaFilled(true); // Fill content area
        button.setBorderPainted(true); // Show border
        
        // Hover effect
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                button.setBackground(BUTTON_HOVER); // Change color on hover
                button.setBorder(BorderFactory.createCompoundBorder( // Update border on hover
                    BorderFactory.createLineBorder(BUTTON_HOVER.darker(), 1),
                    BorderFactory.createEmptyBorder(12, 24, 12, 24)
                ));
            }
            
            public void mouseExited(java.awt.event.MouseEvent evt) {
                button.setBackground(ACCENT_COLOR); // Restore original color
                button.setBorder(BorderFactory.createCompoundBorder( // Restore original border
                    BorderFactory.createLineBorder(ACCENT_COLOR.darker(), 1),
                    BorderFactory.createEmptyBorder(12, 24, 12, 24)
                ));
            }
        });
        
        return button; // Return the styled button
    }
    
    /**
     * Creates a modern panel with card styling
     * @param title The title for the card panel
     * @return A styled JPanel instance
     */
    private static JPanel createCardPanel(String title) {
        JPanel card = new JPanel(); // Create new panel
        card.setBackground(CARD_COLOR); // Set background color
        card.setBorder(BorderFactory.createCompoundBorder( // Create compound border
            BorderFactory.createLineBorder(BORDER_COLOR, 1), // Outer border
            BorderFactory.createEmptyBorder(20, 20, 20, 20) // Inner padding
        ));
        card.setLayout(new BorderLayout()); // Use border layout
        
        if (title != null) {
            JLabel titleLabel = new JLabel(title); // Create title label
            titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16)); // Set title font
            titleLabel.setForeground(TEXT_COLOR); // Set title color
            titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 15, 0)); // Add bottom margin
            card.add(titleLabel, BorderLayout.NORTH); // Add title to top
        }
        
        return card; // Return the styled card panel
    }
    
    /**
     * Creates and displays the main application GUI
     * OOP CONCEPT: Encapsulation - GUI setup logic contained in one method
     */
    private static void createAndShowGUI() {
        // Initialize main window
        frame = new JFrame("Browser History Analyzer with VirusTotal"); // Create main window with title
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); // Exit application when window closed
        frame.setSize(1400, 950); // Set window size
        frame.setLayout(new BorderLayout()); // Use border layout
        frame.getContentPane().setBackground(BACKGROUND_COLOR); // Set background color
        
        // Add window listener to stop server when application closes
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                CommunicationServer.stopServer(); // Stop communication server
                if (dbManager != null) {
                    dbManager.close(); // Close database connection
                }
            }
        });
        
        // Create main panel with grid layout for better organization
        mainPanel = new JPanel(new GridBagLayout()); // Use grid bag layout for flexibility
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20)); // Add padding
        mainPanel.setBackground(BACKGROUND_COLOR); // Set background color
        
        GridBagConstraints gbc = new GridBagConstraints(); // Create layout constraints
        gbc.fill = GridBagConstraints.HORIZONTAL; // Fill horizontally
        gbc.weightx = 1.0; // Take available horizontal space
        gbc.insets = new Insets(0, 0, 15, 0); // Spacing between components
        
        // Header section - Row 0
        JPanel headerPanel = createCardPanel(null); // Create header panel without title
        headerPanel.setLayout(new BorderLayout()); // Use border layout
        
        JLabel titleLabel = new JLabel("Browser History Security Analyzer"); // Main title
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 28)); // Large font for title
        titleLabel.setForeground(TEXT_COLOR); // White text color
        titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0)); // Bottom margin
        
        JLabel subtitleLabel = new JLabel("Professional-grade browser history scanning with VirusTotal API integration"); // Subtitle
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14)); // Smaller font for subtitle
        subtitleLabel.setForeground(LIGHT_TEXT_COLOR); // Light gray text color
        
        headerPanel.add(titleLabel, BorderLayout.NORTH); // Add title to top
        headerPanel.add(subtitleLabel, BorderLayout.CENTER); // Add subtitle to center
        
        gbc.gridx = 0; // Column 0
        gbc.gridy = 0; // Row 0
        gbc.gridwidth = 2; // Span 2 columns
        mainPanel.add(headerPanel, gbc); // Add header to main panel
        
        // API Key section - Row 1
        JPanel apiCard = createCardPanel("API Configuration"); // Create API configuration card
        apiCard.setLayout(new BorderLayout()); // Use border layout
        
        JPanel apiPanel = new JPanel(new FlowLayout(FlowLayout.LEFT)); // Use flow layout for API components
        apiPanel.setBackground(CARD_COLOR); // Set background color
        
        JLabel apiLabel = new JLabel("VirusTotal API Key:"); // API key label
        apiLabel.setFont(new Font("Segoe UI", Font.BOLD, 14)); // Bold font
        apiLabel.setForeground(TEXT_COLOR); // White text color
        apiPanel.add(apiLabel); // Add label to panel
        
        apiKeyField = new JTextField(API_KEY, 45); // Create API key text field with current value
        apiKeyField.setFont(new Font("Segoe UI", Font.PLAIN, 14)); // Set font
        apiKeyField.setToolTipText("Enter your VirusTotal API key. Get one from https://www.virustotal.com/"); // Tooltip
        apiKeyField.setBackground(new Color(30, 35, 42)); // Dark background
        apiKeyField.setForeground(TEXT_COLOR); // White text color
        apiKeyField.setCaretColor(TEXT_COLOR); // White cursor color
        apiKeyField.setBorder(BorderFactory.createCompoundBorder( // Styled border
            BorderFactory.createLineBorder(BORDER_COLOR, 1), // Outer border
            BorderFactory.createEmptyBorder(10, 12, 10, 12) // Inner padding
        ));
        apiPanel.add(apiKeyField); // Add text field to panel
        
        JButton saveApiKeyButton = createModernButton("Save API Key"); // Create save button
        saveApiKeyButton.addActionListener(e -> saveApiKey()); // Add click listener
        apiPanel.add(saveApiKeyButton); // Add button to panel
        
        apiCard.add(apiPanel, BorderLayout.CENTER); // Add API panel to card
        
        gbc.gridx = 0; // Column 0
        gbc.gridy = 1; // Row 1
        gbc.gridwidth = 2; // Span 2 columns
        mainPanel.add(apiCard, gbc); // Add API card to main panel
        
        // Server status section - Row 2
        JPanel serverCard = createCardPanel("Server Status"); // Create server status card
        serverCard.setLayout(new BorderLayout()); // Use border layout
        
        JPanel serverPanel = new JPanel(new FlowLayout(FlowLayout.LEFT)); // Use flow layout for server components
        serverPanel.setBackground(CARD_COLOR); // Set background color
        
        JLabel serverStatus = new JLabel("Extension Server: " + // Server status label
            (CommunicationServer.isRunning() ? "Running on port " + CommunicationServer.getPort() : "Stopped"));
        serverStatus.setFont(new Font("Segoe UI", Font.PLAIN, 14)); // Regular font
        serverStatus.setForeground(CommunicationServer.isRunning() ? SUCCESS_COLOR : ERROR_COLOR); // Green if running, red if stopped
        serverPanel.add(serverStatus); // Add status label to panel
        
        JButton restartServerBtn = createModernButton("Restart Server"); // Create restart button
        restartServerBtn.addActionListener(e -> { // Add click listener
            CommunicationServer.stopServer(); // Stop current server
            CommunicationServer.startServer(); // Start new server
            serverStatus.setText("Extension Server: " + // Update status text
                (CommunicationServer.isRunning() ? "Running on port " + CommunicationServer.getPort() : "Stopped"));
            serverStatus.setForeground(CommunicationServer.isRunning() ? SUCCESS_COLOR : ERROR_COLOR); // Update color
        });
        serverPanel.add(restartServerBtn); // Add button to panel
        
        serverCard.add(serverPanel, BorderLayout.CENTER); // Add server panel to card
        
        gbc.gridx = 0; // Column 0
        gbc.gridy = 2; // Row 2
        gbc.gridwidth = 2; // Span 2 columns
        gbc.weightx = 1.0; // Take available space
        mainPanel.add(serverCard, gbc); // Add server card to main panel
        
        // Action buttons section - Row 3
        JPanel actionsCard = createCardPanel("Security Operations"); // Create actions card
        JPanel buttonPanel = new JPanel(new GridLayout(2, 3, 12, 12)); // 2x3 grid for buttons
        buttonPanel.setBackground(CARD_COLOR); // Set background color
        
        // Row 1 buttons
        JButton importButton = createModernButton("Import History File"); // Import file button
        importButton.addActionListener(e -> importHistoryFile()); // Add click listener

        JButton importExtensionButton = createModernButton("Import from Extension"); // Import from extension button
        importExtensionButton.addActionListener(e -> importFromExtension()); // Add click listener

        JButton analyzeButton = createModernButton("Analyze History"); // Analyze button
        analyzeButton.addActionListener(e -> analyzeHistory()); // Add click listener

        // Row 2 buttons
        JButton exportButton = createModernButton("Export Malicious URLs"); // Export button
        exportButton.addActionListener(e -> exportMaliciousUrls()); // Add click listener

        JButton clearButton = createModernButton("Clear All Data"); // Clear data button
        clearButton.setBackground(ERROR_COLOR); // Red color for destructive action
        clearButton.addActionListener(e -> clearAllData()); // Add click listener

        JButton dbButton = createModernButton("Database Tools"); // Database tools button
        dbButton.setBackground(new Color(130, 80, 223)); // Purple color
        dbButton.addActionListener(e -> showDatabaseTools()); // Add click listener

        // Add all buttons to button panel
        buttonPanel.add(importButton);
        buttonPanel.add(importExtensionButton);
        buttonPanel.add(analyzeButton);
        buttonPanel.add(exportButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(dbButton);

        actionsCard.add(buttonPanel, BorderLayout.CENTER); // Add button panel to card
        
        gbc.gridx = 0; // Column 0
        gbc.gridy = 3; // Row 3
        gbc.gridwidth = 2; // Span 2 columns
        gbc.weightx = 1.0; // Take available space
        mainPanel.add(actionsCard, gbc); // Add actions card to main panel
        
        // Progress section - Row 4
        JPanel progressCard = createCardPanel("Scan Progress"); // Create progress card
        progressCard.setLayout(new BorderLayout()); // Use border layout
        
        progressBar = new JProgressBar(0, 100); // Create progress bar (0-100%)
        progressBar.setStringPainted(true); // Show percentage text
        progressBar.setForeground(SUCCESS_COLOR); // Green progress color
        progressBar.setBackground(BORDER_COLOR); // Dark background
        progressBar.setFont(new Font("Segoe UI", Font.BOLD, 12)); // Progress text font
        progressBar.setPreferredSize(new Dimension(100, 25)); // Set size
        
        statusLabel = new JLabel("Ready to scan browser history"); // Status label
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 14)); // Bold font
        statusLabel.setForeground(TEXT_COLOR); // White text color
        
        JPanel progressContent = new JPanel(new BorderLayout(0, 10)); // Content panel with spacing
        progressContent.setBackground(CARD_COLOR); // Set background color
        progressContent.add(progressBar, BorderLayout.NORTH); // Add progress bar to top
        progressContent.add(statusLabel, BorderLayout.CENTER); // Add status label to center
        
        progressCard.add(progressContent, BorderLayout.CENTER); // Add content to card
        
        gbc.gridx = 0; // Column 0
        gbc.gridy = 4; // Row 4
        gbc.gridwidth = 2; // Span 2 columns
        mainPanel.add(progressCard, gbc); // Add progress card to main panel
        
        // Output section - Row 5 (takes remaining space)
        JPanel outputCard = createCardPanel("Scan Results"); // Create output card
        outputCard.setLayout(new BorderLayout()); // Use border layout
        
        outputArea = new JTextArea(18, 80); // Create text area for output
        outputArea.setEditable(false); // Make read-only
        outputArea.setFont(new Font("Consolas", Font.PLAIN, 13)); // Monospace font for output
        outputArea.setBackground(new Color(30, 35, 42)); // Dark background
        outputArea.setForeground(TEXT_COLOR); // White text color
        outputArea.setCaretColor(TEXT_COLOR); // White cursor color
        outputArea.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15)); // Add padding
        
        JScrollPane scrollPane = new JScrollPane(outputArea); // Add text area to scroll pane
        scrollPane.setBorder(BorderFactory.createLineBorder(BORDER_COLOR, 1)); // Add border
        scrollPane.setPreferredSize(new Dimension(800, 350)); // Set size
        
        outputCard.add(scrollPane, BorderLayout.CENTER); // Add scroll pane to card
        
        gbc.gridx = 0; // Column 0
        gbc.gridy = 5; // Row 5
        gbc.gridwidth = 2; // Span 2 columns
        gbc.weighty = 1.0; // Take available vertical space
        gbc.fill = GridBagConstraints.BOTH; // Fill both directions
        mainPanel.add(outputCard, gbc); // Add output card to main panel
        
        // Finalize GUI setup
        frame.add(mainPanel, BorderLayout.CENTER); // Add main panel to frame
        
        // Center the window
        frame.setLocationRelativeTo(null); // Center on screen
        frame.setVisible(true); // Make window visible
        
        // Check if API key is set
        if (API_KEY == null || API_KEY.trim().isEmpty()) {
            showApiKeyWarning(); // Show warning if no API key
        }
        
        // Load any existing history from database
        loadHistoryFromDatabase(); // Load history on startup
    }
    
    /**
     * Shows database tools dialog - UPDATED for professional theme with detailed scan history
     */
    private static void showDatabaseTools() {
        JDialog dbDialog = new JDialog(frame, "Database Management", true);
        dbDialog.setSize(1000, 700);
        dbDialog.setLayout(new BorderLayout());
        dbDialog.setLocationRelativeTo(frame);
        dbDialog.getContentPane().setBackground(BACKGROUND_COLOR);
        
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BorderLayout());
        contentPanel.setBorder(BorderFactory.createEmptyBorder(25, 25, 25, 25));
        contentPanel.setBackground(BACKGROUND_COLOR);
        
        // Title
        JLabel titleLabel = new JLabel("Database Management Console");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        titleLabel.setForeground(TEXT_COLOR);
        titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 20, 0));
        contentPanel.add(titleLabel, BorderLayout.NORTH);
        
        // Database content area with tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(BACKGROUND_COLOR);
        tabbedPane.setForeground(TEXT_COLOR);
        
        // Tab 1: Detailed Scan History
        JTextArea historyArea = new JTextArea();
        historyArea.setEditable(false);
        historyArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        historyArea.setBackground(new Color(30, 35, 42));
        historyArea.setForeground(TEXT_COLOR);
        historyArea.setCaretColor(TEXT_COLOR);
        
        JScrollPane historyScroll = new JScrollPane(historyArea);
        historyScroll.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_COLOR), 
                "Detailed Scan History"
            ),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        tabbedPane.addTab("📊 Scan History", historyScroll);
        
        // Tab 2: Database Content (existing functionality)
        JTextArea dbContentArea = new JTextArea();
        dbContentArea.setEditable(false);
        dbContentArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        dbContentArea.setBackground(new Color(30, 35, 42));
        dbContentArea.setForeground(TEXT_COLOR);
        dbContentArea.setCaretColor(TEXT_COLOR);
        
        JScrollPane contentScroll = new JScrollPane(dbContentArea);
        contentScroll.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_COLOR), 
                "Database Content"
            ),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        tabbedPane.addTab("💾 Database Content", contentScroll);
        
        contentPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.setBackground(BACKGROUND_COLOR);
        
        // New button for detailed scan history
        JButton historyButton = createModernButton("Show Detailed History");
        historyButton.addActionListener(e -> {
            historyArea.setText(""); // Clear previous content
            
            if (dbManager == null) {
                historyArea.append("Database not connected\n");
                return;
            }

            try {
                // Also show in the text area
                String sessionSql = "SELECT id, datetime(session_date, 'localtime') as local_date, " +
                                   "total_urls, malicious_count, scan_duration, malicious_domains " +
                                   "FROM analysis_sessions ORDER BY session_date DESC";
                Statement stmt = dbManager.getConnection().createStatement();
                ResultSet rs = stmt.executeQuery(sessionSql);
                
                historyArea.append("=== DETAILED SCAN HISTORY ===\n\n");
                
                while (rs.next()) {
                    final int sessionId = rs.getInt("id");
                    String localDate = rs.getString("local_date");
                    int totalUrls = rs.getInt("total_urls");
                    int maliciousCount = rs.getInt("malicious_count");
                    long duration = rs.getLong("scan_duration");
                    String maliciousDomains = rs.getString("malicious_domains");
                    
                    historyArea.append("Session ID: " + sessionId + "\n");
                    historyArea.append("Date/Time: " + localDate + " (Your Local Time)\n");
                    historyArea.append("Total URLs: " + totalUrls + "\n");
                    historyArea.append("Malicious Count: " + maliciousCount + "\n");
                    historyArea.append("Duration: " + duration + " seconds\n");
                    
                    if (maliciousDomains != null && !maliciousDomains.isEmpty()) {
                        historyArea.append("Malicious Domains: " + maliciousDomains + "\n");
                    }
                    
                    // Get malicious URLs for this session
                   
                    
                    historyArea.append("\n" + "─".repeat(80) + "\n\n");
                }
                
                rs.close();
                stmt.close();
                
            } catch (Exception ex) {
                historyArea.append("Error reading scan history: " + ex.getMessage() + "\n");
                ex.printStackTrace();
            }
        });
        
        // Existing buttons
        JButton statusButton = createModernButton("Check Status");
        statusButton.addActionListener(e -> {
            dbContentArea.append("\n=== DATABASE STATUS ===\n");
            if (dbManager == null) {
                dbContentArea.append("❌ Database Manager is null\n");
                return;
            }
            
            try {
                String savedApiKey = dbManager.getApiKey();
                dbContentArea.append("✅ Database Connection: ACTIVE\n");
                
                List<HistoryEntry> dbEntries = dbManager.getHistoryEntries();
                dbContentArea.append("📊 History entries: " + dbEntries.size() + "\n");
                
                List<HistoryEntry> maliciousEntries = dbManager.getMaliciousUrls();
                dbContentArea.append("🚫 Malicious URLs: " + maliciousEntries.size() + "\n");
                
                dbContentArea.append("🔑 API Key: " + (savedApiKey != null && !savedApiKey.isEmpty() ? "SAVED" : "NOT SET") + "\n");
                
            } catch (Exception ex) {
                dbContentArea.append("❌ Database Error: " + ex.getMessage() + "\n");
            }
        });
        
        JButton contentButton = createModernButton("Show All Content");
        contentButton.addActionListener(e -> {
            dbContentArea.setText("");
            
            if (dbManager == null) {
                dbContentArea.append("Database not connected\n");
                return;
            }

            try {
                // Show history entries
                List<HistoryEntry> historyEntries = dbManager.getHistoryEntries();
                dbContentArea.append("HISTORY ENTRIES (" + historyEntries.size() + "):\n");
                for (int i = 0; i < historyEntries.size(); i++) {
                    HistoryEntry entry = historyEntries.get(i);
                    dbContentArea.append((i + 1) + ". " + entry.getUrl() + "\n");
                    dbContentArea.append("    Title: " + entry.getTitle() + "\n");
                    dbContentArea.append("    Visits: " + entry.getVisitCount() + "\n");
                    dbContentArea.append("    Last Visit: " + new java.util.Date(entry.getLastVisitTime()) + "\n\n");
                }

                // Show malicious URLs
                List<HistoryEntry> maliciousUrls = dbManager.getMaliciousUrls();
                dbContentArea.append("MALICIOUS URLS (" + maliciousUrls.size() + "):\n");
                for (int i = 0; i < maliciousUrls.size(); i++) {
                    HistoryEntry entry = maliciousUrls.get(i);
                    dbContentArea.append((i + 1) + ". " + entry.getUrl() + "\n");
                    dbContentArea.append("    Title: " + entry.getTitle() + "\n\n");
                }

            } catch (Exception ex) {
                dbContentArea.append("Error reading database: " + ex.getMessage() + "\n");
            }
        });
        
        JButton clearDbButton = createModernButton("Clear Database");
        clearDbButton.setBackground(ERROR_COLOR);
        clearDbButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(
                dbDialog,
                "This will delete ALL data from the database. Continue?",
                "Clear Database",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );
            
            if (result == JOptionPane.YES_OPTION) {
                try {
                    dbManager.clearAllData();
                    dbContentArea.setText("Database cleared successfully!\n");
                    historyArea.setText(""); // Clear history tab too
                    JOptionPane.showMessageDialog(dbDialog, "Database cleared successfully!");
                } catch (Exception ex) {
                    dbContentArea.append("Error clearing database: " + ex.getMessage() + "\n");
                }
            }
        });
        
        JButton closeButton = createModernButton("Close");
        closeButton.addActionListener(e -> dbDialog.dispose());
        
        // Add all buttons to button panel
        buttonPanel.add(historyButton);
        buttonPanel.add(statusButton);
        buttonPanel.add(contentButton);
        buttonPanel.add(clearDbButton);
        buttonPanel.add(closeButton);
        
        contentPanel.add(buttonPanel, BorderLayout.SOUTH);
        dbDialog.add(contentPanel);
        dbDialog.setVisible(true);
    }
    
    /**
     * Saves the API key to database
     */
    private static void saveApiKey() {
        String newApiKey = apiKeyField.getText().trim(); // Get API key from text field
        if (newApiKey.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "Please enter a valid API key", "Error", JOptionPane.ERROR_MESSAGE); // Show error
            return; // Exit if empty
        }
        
        API_KEY = newApiKey; // Update API key in memory
        dbManager.saveApiKey(newApiKey); // Save to database
        JOptionPane.showMessageDialog(frame, "API key saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE); // Show success
    }
    
    /**
     * Shows warning if API key is not set
     */
    private static void showApiKeyWarning() {
        int result = JOptionPane.showConfirmDialog( // Confirmation dialog
            frame,
            "VirusTotal API key is required for scanning.\n" + // Warning message
            "Would you like to get one now?",
            "API Key Required", // Dialog title
            JOptionPane.YES_NO_OPTION, // Yes/No options
            JOptionPane.WARNING_MESSAGE // Warning icon
        );
        
        if (result == JOptionPane.YES_OPTION) {
            try {
                Desktop.getDesktop().browse(new java.net.URI("https://www.virustotal.com/gui/join-us")); // Open browser
            } catch (Exception ex) {
                outputArea.append("Please visit: https://www.virustotal.com/gui/join-us to get an API key\n"); // Fallback message
            }
        }
    }
    
    /**
     * Called when history is received from extension
     * @param entries List of history entries received from browser extension
     */
    public static void onHistoryReceivedFromExtension(List<HistoryEntry> entries) {
        if (outputArea != null) {
            outputArea.append("\n=== HISTORY IMPORT SUCCESSFUL ===\n"); // Success header
            outputArea.append("✅ Successfully received " + entries.size() + " history entries from extension!\n"); // Success message
            outputArea.append("You can now click 'Analyze History' to scan for malicious URLs.\n"); // Instructions
            outputArea.append("==================================\n\n"); // Footer
        }
        
        // Update status label if available
        if (statusLabel != null) {
            statusLabel.setText("Received " + entries.size() + " entries from extension"); // Update status
        }
    }
    
    /**
     * Imports history from browser extension
     */
    private static void importFromExtension() {
        // Check if server is running
        if (!CommunicationServer.isRunning()) {
            outputArea.append("ERROR: Communication server is not running. Cannot connect to extension.\n"); // Error message
            outputArea.append("Please use the file import option instead.\n"); // Suggestion
            return; // Exit if server not running
        }
        
        outputArea.append("Waiting for history data from extension...\n"); // Waiting message
        outputArea.append("Please use the 'Send to Desktop Tool' button in the extension.\n"); // Instructions
        outputArea.append("Server is listening on port " + CommunicationServer.getPort() + "\n"); // Port info
        
        // Check if we already have history from extension
        if (!allHistoryEntries.isEmpty()) {
            outputArea.append("Found " + allHistoryEntries.size() + " history entries from previous import.\n"); // Info message
            outputArea.append("You can now click 'Analyze History' to scan them.\n"); // Instructions
        }
    }
    
    /**
     * Filters out invalid URLs from history entries
     * @param entries List of history entries to filter
     * @return List of valid history entries
     */
    private static List<HistoryEntry> filterValidUrls(List<HistoryEntry> entries) {
        List<HistoryEntry> validUrls = new ArrayList<>(); // List for valid URLs
        
        for (HistoryEntry entry : entries) {
            String url = entry.getUrl(); // Get URL from entry
            
            // Skip invalid URLs
            if (url == null || url.trim().isEmpty()) {
                continue; // Skip null or empty URLs
            }
            
            // Skip VirusTotal's own URLs and internal pages
            if (url.contains("virustotal.com") || url.contains("virustotalcloud") || 
                url.contains("chrome://") || url.contains("about:") || 
                url.contains("localhost") || url.contains("127.0.0.1")) {
                continue; // Skip internal/self-referential URLs
            }
            
            // Skip malformed URLs
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                continue; // Skip non-HTTP URLs
            }
            
            // Skip very long URLs (might be malformed)
            if (url.length() > 500) {
                continue; // Skip overly long URLs
            }
            
            validUrls.add(entry); // Add valid URL to list
        }
        
        return validUrls; // Return filtered list
    }
    
    /**
     * Main analysis method - coordinates the URL scanning process
     * UPDATED: Ensures malicious URLs are PERMANENTLY saved to database with session linking
     */
    private static void analyzeHistory() {
        // Check API key
        if (API_KEY == null || API_KEY.trim().isEmpty()) {
            outputArea.append("ERROR: Please set your VirusTotal API key first.\n"); // Error message
            showApiKeyWarning(); // Show API key warning
            return; // Exit if no API key
        }
        
        // Check if we have imported history from extension or file
        if (allHistoryEntries.isEmpty()) {
            outputArea.append("Analyzing history with VirusTotal...\n"); // Starting message
            
            // Only read from browser if no history was imported
            allHistoryEntries = HistoryParser.getHistory("Google Chrome"); // Get browser history
            
            // Save to database
            if (!allHistoryEntries.isEmpty()) {
                dbManager.saveHistoryEntries(allHistoryEntries); // Save history to database
            }
        } else {
            // We have imported history
            outputArea.append("Analyzing imported history with VirusTotal...\n"); // Info message
        }
        
        if (allHistoryEntries.isEmpty()) {
            outputArea.append("No history entries found. Please import a history file first.\n"); // Error message
            return; // Exit if no history
        }
        
        // Filter out invalid URLs
        List<HistoryEntry> filteredEntries = filterValidUrls(allHistoryEntries); // Filter URLs
        int filteredCount = allHistoryEntries.size() - filteredEntries.size(); // Count filtered URLs
        if (filteredCount > 0) {
            outputArea.append("Filtered out " + filteredCount + " invalid/internal URLs.\n"); // Filter info
        }
        
        if (filteredEntries.isEmpty()) {
            outputArea.append("No valid URLs to scan after filtering.\n"); // Error message
            return; // Exit if no valid URLs
        }
        
        outputArea.append("Found " + filteredEntries.size() + " valid URLs. Scanning with VirusTotal...\n"); // Scan info
        outputArea.append("Note: Free VirusTotal API allows only " + MAX_URLS_TO_SCAN + " scans per minute.\n"); // API limit info
        
        // Run in background thread to keep UI responsive
        new Thread(() -> {
            final int[] currentSessionId = {-1};
            try {
                long startTime = System.currentTimeMillis(); // Start timing the scan
                
                // Reset malicious URLs in memory (they will be reloaded from database)
                maliciousUrls.clear(); // Clear current malicious URLs
                
                // Limit the number of URLs to scan to respect API limits
                final List<HistoryEntry> urlsToScan;
                if (filteredEntries.size() > MAX_URLS_TO_SCAN) {
                    urlsToScan = filteredEntries.subList(0, MAX_URLS_TO_SCAN); // Take first MAX_URLS_TO_SCAN
                    outputArea.append("Limiting scan to " + MAX_URLS_TO_SCAN + " URLs due to API limits.\n"); // Limit info
                } else {
                    urlsToScan = filteredEntries; // Use all filtered entries
                }
                
                // Initialize progress bar
                progressBar.setMaximum(urlsToScan.size()); // Set max value to number of URLs
                progressBar.setValue(0); // Reset to zero
                
                // Use single thread with proper rate limiting
                executorService = Executors.newSingleThreadExecutor(); // Create single-thread executor
                
                // Reset request counter and timer for rate limiting
                requestCount = 0; // Reset request counter
                minuteStartTime = System.currentTimeMillis(); // Reset minute timer
                
                // Create list to collect malicious domains for the session
                List<String> maliciousDomains = new ArrayList<>();
                
                // Scan each URL with VirusTotal with proper rate limiting
                for (int i = 0; i < urlsToScan.size(); i++) {
                    final HistoryEntry entry = urlsToScan.get(i); // Get current entry
                    final int index = i; // Store index for progress tracking
                    
                    executorService.submit(() -> {
                        try {
                            statusLabel.setText("Scanning URL " + (index + 1) + " of " + urlsToScan.size()); // Update status
                            
                            // Enforce rate limiting to avoid API restrictions
                            enforceRateLimit(); // Wait if needed
                            
                            // INHERITANCE: Using the ScanResult base class type
                            ScanResult result = scanUrlWithVirusTotal(entry.getUrl()); // Scan URL with VirusTotal
                            
                            if (result.isMalicious()) {
                                // POLYMORPHISM: We know it's a VTScanResult but use base class interface
                                VTScanResult vtResult = (VTScanResult) result; // Cast to specific type
                                outputArea.append("🚫 MALICIOUS (" + vtResult.getPositives() + "/" + vtResult.getTotal() + "): " + entry.getUrl() + "\n"); // Malicious result
                                maliciousUrls.add(entry); // Add to memory list
                                
                                // Extract domain for session tracking
                                String domain = extractDomain(entry.getUrl());
                                if (!maliciousDomains.contains(domain)) {
                                    maliciousDomains.add(domain);
                                }
                                
                                // CRITICAL: Save malicious URL to PERMANENT database storage with session linking
                                boolean saved = dbManager.saveMaliciousUrl(entry, vtResult.getPositives(), vtResult.getTotal(), currentSessionId[0]);
                                if (saved) {
                                    outputArea.append("   💾 PERMANENTLY saved to database\n"); // Success message
                                } else {
                                    outputArea.append("   ❌ FAILED to save to database\n"); // Error message
                                }
                            } else if (result.getError() != null) {
                                if (result.getError().contains("not in VT database")) {
                                    outputArea.append("ℹ️ INFO: " + result.getError() + ": " + entry.getUrl() + "\n"); // Info message
                                } else {
                                    outputArea.append("❌ ERROR: " + result.getError() + ": " + entry.getUrl() + "\n"); // Error message
                                }
                            } else {
                                outputArea.append("✅ CLEAN: " + entry.getUrl() + "\n"); // Clean result
                            }
                            
                            // Update progress
                            SwingUtilities.invokeLater(() -> {
                                progressBar.setValue(progressBar.getValue() + 1); // Increment progress bar
                            });
                            
                        } catch (Exception ex) {
                            outputArea.append("❌ Error scanning URL: " + entry.getUrl() + " - " + ex.getMessage() + "\n"); // Error message
                        }
                    });
                    
                    // Add small delay between scheduling tasks
                    Thread.sleep(100); // Brief delay to prevent overwhelming the executor
                }
                
                // Shutdown executor and wait for completion
                executorService.shutdown(); // Initiate shutdown
                executorService.awaitTermination(2, TimeUnit.HOURS); // Wait for completion (max 2 hours)
                
                long endTime = System.currentTimeMillis(); // End timing
                long duration = (endTime - startTime) / 1000; // Calculate duration in seconds
                
                outputArea.append("\n🎉 Scan complete. Found " + maliciousUrls.size() + " malicious URLs in " + duration + " seconds.\n"); // Completion message
                statusLabel.setText("Scan complete. Found " + maliciousUrls.size() + " malicious URLs."); // Update status
                
                currentSessionId[0] = dbManager.saveAnalysisSession(urlsToScan.size(), maliciousUrls.size(), duration, maliciousDomains);

if (currentSessionId[0] != -1) {
    outputArea.append("💾 Scan session saved with ID: " + currentSessionId[0] + "\n");
}
                
            } catch (Exception ex) {
                outputArea.append("❌ Error during analysis: " + ex.getMessage() + "\n"); // Error message
                ex.printStackTrace(); // Print stack trace for debugging
            }
        }).start(); // Start the background thread
    }
    
    /**
     * Enforces rate limiting for VirusTotal API requests
     */
    private static void enforceRateLimit() {
        synchronized (rateLimitLock) { // Synchronize for thread safety
            long currentTime = System.currentTimeMillis(); // Get current time
            
            // Reset counter if more than a minute has passed
            if (currentTime - minuteStartTime > 60000) { // Check if minute has elapsed
                requestCount = 0; // Reset request counter
                minuteStartTime = currentTime; // Reset minute start time
            }
            
            // Check if we've reached the limit
            if (requestCount >= MAX_REQUESTS_PER_MINUTE) { // Check if at limit
                long waitTime = 61000 - (currentTime - minuteStartTime); // Calculate wait time
                outputArea.append("⏳ API limit reached. Waiting " + (waitTime/1000) + " seconds before continuing...\n"); // Wait message
                try {
                    Thread.sleep(waitTime); // Wait for remaining time in minute
                    requestCount = 0; // Reset counter after waiting
                    minuteStartTime = System.currentTimeMillis(); // Reset minute timer
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); // Restore interrupt status
                }
            }
            
            // Ensure minimum delay between requests
            long timeSinceLastRequest = currentTime - lastRequestTime; // Calculate time since last request
            if (timeSinceLastRequest < VT_RATE_LIMIT_DELAY) { // Check if delay needed
                try {
                    Thread.sleep(VT_RATE_LIMIT_DELAY - timeSinceLastRequest); // Wait for remaining delay
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); // Restore interrupt status
                }
            }
            
            lastRequestTime = System.currentTimeMillis(); // Update last request time
            requestCount++; // Increment request counter
        }
    }
    
    /**
     * Simple JSON parser for VirusTotal response
     * @param json JSON string to parse
     * @return Map of key-value pairs from JSON
     */
    private static Map<String, String> parseSimpleJson(String json) {
        Map<String, String> result = new HashMap<>(); // Create result map
        if (json == null || json.trim().isEmpty()) {
            return result; // Return empty map if null or empty
        }
        
        // Remove curly braces
        String cleanJson = json.trim(); // Trim whitespace
        if (cleanJson.startsWith("{") && cleanJson.endsWith("}")) {
            cleanJson = cleanJson.substring(1, cleanJson.length() - 1).trim(); // Remove braces
        }
        
        // Split into key-value pairs
        String[] pairs = cleanJson.split(","); // Split by commas
        for (String pair : pairs) {
            String[] keyValue = pair.split(":", 2); // Split into key and value
            if (keyValue.length == 2) {
                String key = keyValue[0].trim().replace("\"", ""); // Clean key
                String value = keyValue[1].trim().replace("\"", ""); // Clean value
                result.put(key, value); // Add to map
            }
        }
        
        return result; // Return parsed map
    }
    
    /**
     * Scans a URL with VirusTotal API
     * @param url The URL to scan
     * @return ScanResult object with scan results
     */
    private static ScanResult scanUrlWithVirusTotal(String url) {
        VTScanResult result = new VTScanResult(); // Create result object
        
        try {
            String encodedUrl = URLEncoder.encode(url, "UTF-8"); // URL encode the parameter
            URL vtUrl = new URL(VT_API_URL + "?apikey=" + API_KEY + "&resource=" + encodedUrl); // Build API URL
            HttpURLConnection conn = (HttpURLConnection) vtUrl.openConnection(); // Open connection
            conn.setRequestMethod("GET"); // Set GET request
            conn.setRequestProperty("User-Agent", "BrowserHistoryAnalyzer/1.0"); // Set user agent
            conn.setConnectTimeout(10000); // Set connection timeout
            conn.setReadTimeout(10000); // Set read timeout
            
            int responseCode = conn.getResponseCode(); // Get HTTP response code
            
            if (responseCode == 200) { // Success
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream())); // Create reader
                String inputLine;
                StringBuilder response = new StringBuilder(); // Create response builder
                
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine); // Append each line
                }
                in.close(); // Close reader
                
                // Parse JSON response using our simple parser
                Map<String, String> jsonResponse = parseSimpleJson(response.toString()); // Parse response
                
                // Check response code
                String responseCodeStr = jsonResponse.get("response_code"); // Get response code
                if (responseCodeStr != null && responseCodeStr.equals("0")) {
                    result.setError("URL not in VT database"); // Set error
                    return result; // Return early
                }
                
                // Get scan results
                String positivesStr = jsonResponse.get("positives"); // Get positives count
                String totalStr = jsonResponse.get("total"); // Get total scans count
                
                if (positivesStr != null && totalStr != null) {
                    try {
                        int positives = Integer.parseInt(positivesStr); // Parse positives
                        int total = Integer.parseInt(totalStr); // Parse total
                        result.setScanResults(positives, total); // Set scan results
                    } catch (NumberFormatException e) {
                        result.setError("Invalid scan results format"); // Set format error
                    }
                } else {
                    result.setError("Missing scan results in response"); // Set missing results error
                }
            } else if (responseCode == 204) {
                // API rate limit exceeded
                result.setError("Rate limit exceeded - waiting before next request"); // Set rate limit error
                // Wait longer when we hit rate limit
                try {
                    Thread.sleep(30000); // Wait 30 seconds
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); // Restore interrupt status
                }
            } else if (responseCode == 403) {
                result.setError("API key invalid (403)"); // Set auth error
            } else if (responseCode == 400) {
                result.setError("Bad request (400)"); // Set bad request error
            } else {
                result.setError("HTTP error: " + responseCode); // Set generic HTTP error
            }
        } catch (Exception ex) {
            result.setError("Network error: " + ex.getMessage()); // Set network error
        }
        
        return result; // Return scan result
    }
    
    /**
     * Imports history file from user selection
     */
    private static void importHistoryFile() {
        JFileChooser fileChooser = new JFileChooser(); // Create file chooser
        fileChooser.setDialogTitle("Select Browser History File"); // Set dialog title
        
        // Clear all file filters first
        for (javax.swing.filechooser.FileFilter filter : fileChooser.getChoosableFileFilters()) {
            fileChooser.removeChoosableFileFilter(filter); // Remove default filters
        }
        
        // Add specific file filters
        fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("CSV Files", "csv")); // CSV filter
        fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("SQLite Database", "sqlite", "db")); // SQLite filter
        fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("JSON Files", "json")); // JSON filter
        fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("All Files", "*")); // All files filter
        
        // Set default filter to CSV
        fileChooser.setFileFilter(new FileNameExtensionFilter("CSV Files", "csv")); // Set CSV as default
        
        int result = fileChooser.showOpenDialog(frame); // Show open dialog
        if (result == JFileChooser.APPROVE_OPTION) { // If file selected
            File selectedFile = fileChooser.getSelectedFile(); // Get selected file
            outputArea.append("Importing history from: " + selectedFile.getName() + "\n"); // Import message
            
            try {
                // Parse the imported file
                allHistoryEntries = HistoryParser.parseHistoryFile(selectedFile, "browser"); // Parse file
                outputArea.append("✅ Imported " + allHistoryEntries.size() + " history entries.\n"); // Success message
                
                // Save to database
                dbManager.saveHistoryEntries(allHistoryEntries); // Save to database
                
            } catch (Exception ex) {
                outputArea.append("❌ Error importing file: " + ex.getMessage() + "\n"); // Error message
                if (selectedFile.getName().toLowerCase().endsWith(".csv")) {
                    outputArea.append("Make sure the CSV file is in the correct format for browser history.\n"); // CSV help
                }
            }
        }
    }
    
    /**
     * Exports malicious URLs to JSON file with domain extraction
     */
    private static void exportMaliciousUrls() {
        if (maliciousUrls.isEmpty()) {
            outputArea.append("No malicious URLs to export.\n"); // No data message
            return; // Exit if nothing to export
        }
        
        JFileChooser fileChooser = new JFileChooser(); // Create file chooser
        fileChooser.setDialogTitle("Save Malicious Domains as JSON"); // Set dialog title
        fileChooser.setFileFilter(new FileNameExtensionFilter("JSON Files", "json")); // JSON filter
        
        int result = fileChooser.showSaveDialog(frame); // Show save dialog
        if (result == JFileChooser.APPROVE_OPTION) { // If location selected
            File file = fileChooser.getSelectedFile(); // Get selected file
            if (!file.getName().toLowerCase().endsWith(".json")) {
                file = new File(file.getAbsolutePath() + ".json"); // Add .json extension if missing
            }
            
            try (FileWriter writer = new FileWriter(file)) { // Create file writer
                // Extract domains from URLs
                Set<String> uniqueDomains = new LinkedHashSet<>(); // Use set to avoid duplicates
                for (HistoryEntry entry : maliciousUrls) {
                    String domain = extractDomain(entry.getUrl()); // Extract domain from URL
                    if (domain != null && !domain.isEmpty()) {
                        uniqueDomains.add(domain); // Add to domain set
                    }
                }
                
                // Create JSON with domains for extension
                writer.write("{\n"); // Start JSON object
                writer.write("  \"version\": \"1.0\",\n"); // Version field
                writer.write("  \"domains\": [\n"); // Start domains array
                
                int count = 0; // Counter for formatting
                for (String domain : uniqueDomains) {
                    writer.write("    \"" + domain.replace("\"", "\\\"") + "\""); // Write domain (escape quotes)
                    if (++count < uniqueDomains.size()) {
                        writer.write(","); // Add comma if not last
                    }
                    writer.write("\n"); // New line
                }
                
                writer.write("  ]\n"); // End domains array
                writer.write("}\n"); // End JSON object
                
                outputArea.append("✅ Exported " + uniqueDomains.size() + " malicious domains to: " + file.getName() + "\n"); // Success message
                outputArea.append("Use this JSON file in your browser extension to block these domains.\n"); // Instructions
                
            } catch (IOException ex) {
                outputArea.append("❌ Error exporting URLs: " + ex.getMessage() + "\n"); // Error message
            }
        }
    }
    
    /**
     * Clears ALL data including database and memory
     */
    private static void clearAllData() {
        int result = JOptionPane.showConfirmDialog( // Confirmation dialog
            frame,
            "This will clear ALL data including:\n" + // Warning message
            "• Current scan results\n" + 
            "• Imported history\n" +
            "• Database content\n\n" +
            "This action cannot be undone. Continue?",
            "Clear All Data", // Dialog title
            JOptionPane.YES_NO_OPTION, // Yes/No options
            JOptionPane.WARNING_MESSAGE // Warning icon
        );
        
        if (result == JOptionPane.YES_OPTION) { // If confirmed
            try {
                // Clear memory
                allHistoryEntries.clear(); // Clear history entries
                maliciousUrls.clear(); // Clear malicious URLs
                outputArea.setText(""); // Clear output area
                progressBar.setValue(0); // Reset progress bar
                statusLabel.setText("Ready to scan browser history"); // Reset status
                
                // Clear database
                if (dbManager != null) {
                    dbManager.clearAllData(); // Clear database
                }
                
                outputArea.append("✅ All data cleared successfully.\n"); // Success message
                outputArea.append("Memory and database have been reset.\n"); // Reset confirmation
                
            } catch (Exception ex) {
                outputArea.append("❌ Error clearing data: " + ex.getMessage() + "\n"); // Error message
            }
        }
    }
    
    /**
     * Extracts domain from URL
     * @param url The URL to extract domain from
     * @return The extracted domain
     */
    private static String extractDomain(String url) {
        try {
            java.net.URL urlObj = new java.net.URL(url); // Create URL object
            String domain = urlObj.getHost(); // Extract host (domain)
            // Remove www prefix if present
            if (domain.startsWith("www.")) {
                domain = domain.substring(4); // Remove 'www.'
            }
            return domain; // Return cleaned domain
        } catch (Exception e) {
            // Fallback: simple domain extraction
            String cleanUrl = url.replace("https://", "").replace("http://", ""); // Remove protocol
            int slashIndex = cleanUrl.indexOf('/'); // Find first slash
            if (slashIndex > 0) {
                cleanUrl = cleanUrl.substring(0, slashIndex); // Take only domain part
            }
            if (cleanUrl.startsWith("www.")) {
                cleanUrl = cleanUrl.substring(4); // Remove 'www.'
            }
            return cleanUrl; // Return fallback domain
        }
    }
    
    // NEW METHODS FOR COMMUNICATIONSERVER - Add these before the last closing brace

    /**
     * Updates history entries in memory - used by CommunicationServer
     * @param entries List of history entries to update
     */
    public static void updateHistoryEntries(List<HistoryEntry> entries) {
        if (entries != null && !entries.isEmpty()) { // Check if entries are valid
            allHistoryEntries = entries; // Replace current history
            System.out.println("✅ Updated history entries: " + entries.size() + " entries"); // Log update
            
            // Save to database
            if (dbManager != null) {
                dbManager.saveHistoryEntries(entries); // Save to database
            }
            
            // Update UI if available
            if (outputArea != null) {
                outputArea.append("✅ Received " + entries.size() + " history entries from extension\n"); // UI update
            }
        }
    }

    /**
     * Gets current history entries for CommunicationServer
     * @return List of current history entries
     */
    public static List<HistoryEntry> getCurrentHistory() {
        return allHistoryEntries; // Return current history
    }

    /**
     * Gets current malicious URLs for CommunicationServer
     * @return List of current malicious URLs
     */
    public static List<HistoryEntry> getCurrentMaliciousUrls() {
        return maliciousUrls; // Return current malicious URLs
    }

    /**
     * Gets all history entries (alias for compatibility)
     * @return List of all history entries
     */
    public static List<HistoryEntry> getAllHistoryEntries() {
        return allHistoryEntries; // Return all history entries
    }

    /**
     * Sets all history entries (alias for compatibility)
     * @param entries List of history entries to set
     */
    public static void setAllHistoryEntries(List<HistoryEntry> entries) {
        allHistoryEntries = entries; // Set history entries
    }

    /**
     * Gets database manager instance
     * @return DatabaseManager instance
     */
    public static DatabaseManager getDbManager() {
        return dbManager; // Return database manager
    }

    /**
     * Gets malicious URLs (alias for compatibility)
     * @return List of malicious URLs
     */
    public static List<HistoryEntry> getMaliciousUrls() {
        return maliciousUrls; // Return malicious URLs
    }
}