# 🛡️ Lightweight Threat Log Analyzer (Mini-SIEM)

**Academic Project:** University of Mumbai | Pillai College of Engineering  
**Course:** Java Programming (TY, Sem V)  
**Developer:** Vedant Mishra  

## 📌 Project Overview
Server and authentication logs represent a critical source of operational telemetry for identifying security incidents. Enterprise-grade Security Information and Event Management (SIEM) platforms often introduce substantial overhead, making them impractical for localized system monitoring. 

This project is a standalone, Java-based threat log analyzer designed to automate the ingestion, parsing, and correlation of event logs. Built with core object-oriented programming principles and Java Swing, it acts as a localized Mini-SIEM, eliminating the need for manual log auditing.

## 🚀 Core Features
* **Memory-Efficient File Streaming:** Utilizes `BufferedReader` to stream massive server logs line-by-line in $O(N)$ time complexity, preventing memory overflow.
* **Stateless Signature Detection:** Evaluates HTTP payloads using string manipulation to instantly flag known attacks such as **SQL Injections** (`DROP TABLE`, `UNION SELECT`) and **Directory Traversals** (`../`, `ETC/PASSWD`).
* **Stateful Behavioral Tracking:** Uses `HashMap<String, Integer>` data structures to achieve $O(1)$ constant-time tracking of IP addresses, accurately identifying **Brute-Force Authentication** attempts over sliding thresholds.
* **Automated Triage:** Generates a consolidated incident report and actionable firewall block directives via a custom dark-mode GUI.

## 💻 Tech Stack
* **Language:** Java (JDK 17+)
* **GUI Framework:** Java Swing / AWT
* **Data Structures:** HashMaps, Arrays
* **I/O Processing:** `java.io` (BufferedReader, FileReader)

## 🛠️ How to Run Locally
1. Ensure Java is installed on your system.
2. Clone this repository or download the files.
3. Compile the Java file via terminal:
   ```bash
   javac LogAnalyzer.java
