# Network Traffic Analysis and Anomaly Detection

This project involves analyzing network traffic data from a pcap file and detecting anomalies using machine learning techniques.

## Table of Contents
- [Introduction](#introduction)
- [Requirements](#requirements)
- [Usage](#usage)
- [Methodology](#methodology)
- [Results](#results)
- [Conclusion](#conclusion)

## Introduction
Network traffic analysis is a crucial task in cybersecurity to identify potential threats and anomalies. This project aims to analyze network traffic data from a pcap file and detect anomalies using machine learning techniques.

## Requirements
- Python 3.x
- Scapy
- Pandas
- Matplotlib
- Scikit-learn
- ipaddress

## Usage
1. Clone the repository:
    ```bash
    git clone https://github.com/sayantancodex/Advanced-Network-Traffic-Analysis-and-Anomaly-Detection.git
    ```
2. Install the required libraries:
    ```bash
    pip install -r requirements.txt
    ```
3. Run the script:
    ```bash
    python main.py
    ```

## Methodology
1. Read the pcap file using Scapy.
2. Extract relevant packet information (source IP, destination IP, protocol, timestamp, etc.).
3. Create a Pandas DataFrame from the extracted data.
4. Perform exploratory data analysis (EDA) to understand the distribution of protocols, top talkers, and traffic volume over time.
5. Use the most active IPs as known malicious IPs.
6. Train an Isolation Forest model to detect anomalies.
7. Predict anomalies and save them to a CSV file.

## Results
The script generates several plots and CSV files, including:
- Top 20 source IPs
- Top 20 destination IPs
- Protocol distribution
- Traffic volume over time
- Detected threats (known malicious IPs)
- Detected anomalies (using Isolation Forest)
- Anomalies CSV file

## Conclusion
This project demonstrates the use of machine learning techniques to detect anomalies in network traffic data. The results show that the Isolation Forest model is effective in identifying potential threats and anomalies. This project can be extended to include more advanced techniques, such as deep learning, and to analyze larger datasets.
