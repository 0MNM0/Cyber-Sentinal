# Cyber-Sentinal
An integrated light weight Network Monitoring System, with Wazuh and ELK stack.
CyberSentinel - Advanced Network Security Monitoring System
CyberSentinel is a comprehensive security monitoring tool designed for Local Area Networks (LAN) that can detect and alert on various traditional attack vectors in real-time. Built specifically for small businesses, startups, homes, and educational institutions, it provides enterprise-grade security monitoring capabilities without the complexity of enterprise solutions.

🎯 Project Overview
Our project addresses the critical need for accessible cybersecurity monitoring in environments where traditional enterprise solutions are either too expensive or too complex. CyberSentinel detects a wide range of real-world attacks including:

Aggressive network scans and reconnaissance activities
DDoS attacks and network flooding
Brute force attacks on services and applications
SQL injection attempts and web-based attacks
Shellshock vulnerabilities and command injection
Meterpreter attacks and advanced persistent threats
System-level intrusions and unauthorized access attempts
🏗️ Technical Architecture
Core Components
Wazuh Manager - The heart of the system

Collects and analyzes security events from agents
Generates alerts based on predefined rules
Manages agent connections and configurations
Stores alerts in alerts.json for further processing
ELK Stack Integration

Elasticsearch: Stores and indexes all security logs and alerts
Logstash: Processes, filters, and formats logs; handles HTML email notifications
Kibana: Provides beautiful visual dashboards for security monitoring
Filebeat/Packetbeat: Forwards Wazuh alerts to Elasticsearch
Suricata - Network-based attack detection

Detects network-level attacks that Wazuh might miss
Generates its own logs and alerts
Forwards network alerts to Wazuh for centralized processing
Installed on each agent for comprehensive coverage
Honeypot Integration (In Development)

Traps attackers and records their activities
Captures exact IP addresses, attack commands, and timestamps
Currently integrated only in the manager
