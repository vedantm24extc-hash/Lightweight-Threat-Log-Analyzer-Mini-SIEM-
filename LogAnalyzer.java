import java.io.*;
import java.util.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class LogAnalyzer {

    private static JTextArea resultArea;

    public static void main(String[] args) {
        // Removed the Windows Look-and-Feel override so our custom colors work properly

        JFrame frame = new JFrame("Threat Log Analyzer (Mini-SIEM)");
        frame.setSize(850, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());
        frame.getContentPane().setBackground(new Color(30, 30, 30));

        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 20, 15));
        headerPanel.setBackground(new Color(45, 45, 48));
        headerPanel.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, new Color(70, 70, 70))); 

        // Removed emojis to fix the square box issue
        JLabel titleLabel = new JLabel("Security Event Monitor");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 22));
        titleLabel.setForeground(Color.WHITE);

        JButton uploadButton = new JButton("Select Log File");
        uploadButton.setFont(new Font("Segoe UI", Font.BOLD, 14));
        uploadButton.setBackground(new Color(72, 118, 255)); // This blue will now show up
        uploadButton.setForeground(Color.WHITE);
        uploadButton.setFocusPainted(false);
        uploadButton.setCursor(new Cursor(Cursor.HAND_CURSOR));

        headerPanel.add(titleLabel);
        headerPanel.add(uploadButton);

        resultArea = new JTextArea();
        resultArea.setEditable(false);
        resultArea.setFont(new Font("Consolas", Font.PLAIN, 14)); 
        resultArea.setBackground(new Color(15, 15, 15)); 
        resultArea.setForeground(new Color(0, 255, 0));  
        resultArea.setMargin(new Insets(10, 15, 10, 15)); 

        JScrollPane scrollPane = new JScrollPane(resultArea);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(70, 70, 70), 1));

        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBackground(new Color(30, 30, 30));
        centerPanel.setBorder(new EmptyBorder(15, 20, 20, 20)); 
        centerPanel.add(scrollPane, BorderLayout.CENTER);

        uploadButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int response = fileChooser.showOpenDialog(frame);
            
            if (response == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                resultArea.setText(""); 
                resultArea.append(">>> INITIALIZING THREAT LOG ANALYZER...\n");
                resultArea.append(">>> TARGET FILE: " + file.getName() + "\n");
                resultArea.append("============================================================\n\n");
                
                analyzeLogFile(file.getAbsolutePath());
                
                resultArea.append("\n============================================================\n");
                resultArea.append(">>> ANALYSIS COMPLETE.\n");
            }
        });

        frame.add(headerPanel, BorderLayout.NORTH);
        frame.add(centerPanel, BorderLayout.CENTER);

        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    public static void analyzeLogFile(String filePath) {
        HashMap<String, Integer> failedLoginCounts = new HashMap<>();

        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                checkForSQLInjection(line);
                trackFailedLogins(line, failedLoginCounts);
            }
        } catch (IOException e) {
            resultArea.append("[ERROR] Failed to read the file: " + e.getMessage() + "\n");
        }
        
        printBruteForceReport(failedLoginCounts);
    }

    public static void checkForSQLInjection(String logLine) {
        String upperLine = logLine.toUpperCase(); 
        if (upperLine.contains("DROP TABLE") || upperLine.contains("UNION SELECT")) {
            resultArea.append("[ALERT] SQL Injection attempt detected:\n  -> " + logLine + "\n");
        } else if (logLine.contains("../") || logLine.contains("ETC/PASSWD")) {
            resultArea.append("[ALERT] Directory Traversal attempt detected:\n  -> " + logLine + "\n");
        }
    }

    public static void trackFailedLogins(String logLine, HashMap<String, Integer> counts) {
        if (logLine.contains("401") || logLine.contains("Failed password")) {
            String[] parts = logLine.split(" "); 
            String ipAddress = parts[0]; 
            counts.put(ipAddress, counts.getOrDefault(ipAddress, 0) + 1);
        }
    }

    public static void printBruteForceReport(HashMap<String, Integer> counts) {
        resultArea.append("\n--- BRUTE FORCE REPORT ---\n");
        int threshold = 3; 
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            String ip = entry.getKey();
            int attempts = entry.getValue();
            if (attempts >= threshold) {
                resultArea.append("[WARNING] Block IP: " + ip + " - " + attempts + " failed attempts.\n");
            }
        }
    }
}