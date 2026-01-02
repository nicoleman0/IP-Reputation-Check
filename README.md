# IP Reputation Check

![License](https://img.shields.io/badge/license-ISC-blue.svg)
![Node](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)
![Express](https://img.shields.io/badge/express-5.2.1-lightgrey.svg)
![APIs](https://img.shields.io/badge/APIs-AbuseIPDB%20%7C%20VirusTotal-orange.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

A web application for checking IP address reputation using the AbuseIPDB and VirusTotal APIs.

## Description

This app provides a simple interface to query IP addresses and retrieve detailed threat intelligence information. It combines data from AbuseIPDB (abuse reports) and VirusTotal (security vendor detections) to give comprehensive threat assessments including abuse confidence scores, geographic location, ISP details, threat level classifications, and malware detection rates.

## Features

- IP address validation (IPv4 and IPv6)
- **Dual-source threat intelligence:**
  - AbuseIPDB abuse confidence scoring and report history
  - VirusTotal detection from 70+ security vendors
- Geographic and ISP information
- Threat level classification (Minimal, Low, Medium, High Risk)
- Domain reputation checking
- URL scanning capabilities
- File hash lookups (MD5, SHA1, SHA256)
- Clean, user-friendly interface

## Prerequisites

- Node.js (v14 or higher)
- AbuseIPDB API key ([Get one here](https://www.abuseipdb.com/api))
- VirusTotal API key ([Get one here](https://www.virustotal.com/gui/join-us))

## Installation

1. Clone the repository:
```bash
git clone https://github.com/nicoleman0/IP-Reputation-Check
cd IP-Reputation-Check
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory:
```bash
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

## Usage

1. Start the server:
```bash
npm start
```

2. Open your browser and navigate to:
```
http://localhost:3000
```

3. Enter an IP address to check its threat information

## API Endpoints

### POST /api/ip

Check an IP address for abuse reports and threat intelligence from both AbuseIPDB and VirusTotal.

**Request Body:**
```json
{
  "ip": "8.8.8.8"
}
```

**Response:**
```json
{
  "ip": "8.8.8.8",
  "abuseipdb": {
    "ipAddress": "8.8.8.8",
    "isPublic": true,
    "ipVersion": 4,
    "isWhitelisted": false,
    "abuseConfidenceScore": 0,
    "countryCode": "US",
    "countryName": "United States",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Google LLC",
    "domain": "google.com",
    "hostnames": ["dns.google"],
    "totalReports": 0,
    "numDistinctUsers": 0,
    "lastReportedAt": "Never reported",
    "threatLevel": "Minimal Risk",
    "summary": "This IP from United States has no abuse reports."
  },
  "virustotal": {
    "ipAddress": "8.8.8.8",
    "malicious": 0,
    "suspicious": 0,
    "harmless": 85,
    "undetected": 0,
    "totalScans": 85,
    "detectionRate": "0/85",
    "country": "US",
    "asOwner": "GOOGLE",
    "reputation": 1450,
    "threatLevel": "Clean",
    "lastAnalysisDate": "1/2/2026, 12:00:00 PM",
    "summary": "Clean: 0 security vendors flagged this IP as malicious (85 total)."
  }
}
```

### POST /api/virustotal/domain

Check a domain's reputation on VirusTotal.

**Request Body:**
```json
{
  "domain": "example.com"
}
```

**Response:**
```json
{
  "domain": "example.com",
  "malicious": 0,
  "suspicious": 0,
  "harmless": 78,
  "undetected": 7,
  "totalScans": 85,
  "detectionRate": "0/85",
  "reputation": 120,
  "categories": {},
  "lastAnalysisDate": "1/2/2026, 12:00:00 PM"
}
```

### POST /api/virustotal/url

Scan a URL for threats on VirusTotal.

**Request Body:**
```json
{
  "url": "https://example.com/page"
}
```

**Response:**
```json
{
  "url": "https://example.com/page",
  "malicious": 0,
  "suspicious": 0,
  "harmless": 82,
  "undetected": 3,
  "totalScans": 85,
  "detectionRate": "0/85",
  "status": "completed"
}
```

### POST /api/virustotal/hash

Lookup a file hash (MD5, SHA1, or SHA256) on VirusTotal.

**Request Body:**
```json
{
  "hash": "44d88612fea8a8f36de82e1278abb02f"
}
```

**Response:**
```json
{
  "hash": "44d88612fea8a8f36de82e1278abb02f",
  "fileName": "sample.exe",
  "fileType": "Win32 EXE",
  "fileSize": 12345,
  "malicious": 0,
  "suspicious": 0,
  "harmless": 75,
  "undetected": 10,
  "totalScans": 85,
  "detectionRate": "0/85",
  "lastAnalysisDate": "1/2/2026, 12:00:00 PM"
}
```

## Dependencies

- **express** - Web server framework
- **axios** - HTTP client for API requests
- **dotenv** - Environment variable management

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

- IP threat intelligence powered by [AbuseIPDB](https://www.abuseipdb.com/)
- Security vendor detections powered by [VirusTotal](https://www.virustotal.com/)
