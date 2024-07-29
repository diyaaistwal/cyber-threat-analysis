# cyber-threat-analysis
Network traffic analysis and security detection

This repository contains a Python script designed to analyze network traffic and detect potential security threats such as port scanning and denial-of-service (DoS) attacks. The script processes PCAP files to extract, analyze, and visualize network packet data, providing insights into bandwidth usage, protocol distribution, and IP communication patterns.

Features:

1. PCAP File Reading: Reads and processes network packets from a specified PCAP file using scapy.

2. Data Extraction: Extracts key data from each packet, including source and destination IP addresses, protocol type, and packet size.

3. Traffic Analysis:
-Bandwidth Calculation: Computes the total bandwidth used.
-Protocol Distribution: Analyzes and visualizes the distribution of different protocols.
-IP Communication Patterns: Identifies and tabulates communication patterns between IP addresses.

4. Security Detection:
-Port Scanning Detection: Identifies potential port scanning activities.
-DoS Attack Detection: Detects potential DoS attacks based on packet counts.

5. Visualization: Generates plots for protocol distribution and IP communication patterns.
   
6. Reporting: Formats the analysis results into a structured report (feature currently commented out for debugging).
   
Requirements:
-Python 3.x
-scapy
-pandas
-matplotlib
-tabulate
-tqdm
-logging
-(Optional) python-docx (for generating Word reports)

Reporting:
The function to save the results to a Word document is currently commented out for debugging purposes. To enable it, uncomment the relevant lines in the main function.

Contributing:
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

Acknowledgements:
This project utilizes various open-source libraries, including scapy, pandas, and matplotlib. Special thanks to the developers and contributors of these projects.
