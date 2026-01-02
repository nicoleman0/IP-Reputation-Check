# IP Reputation Check

A web application for checking IP address reputation using the AbuseIPDB API.

## Description

This app provides a simple interface to query IP addresses and retrieve detailed threat intelligence information including abuse confidence scores, geographic location, ISP details, and threat level assessments.

## Features

- IP address validation (IPv4 and IPv6)
- Abuse confidence scoring
- Geographic and ISP information
- Threat level classification (Minimal, Low, Medium, High Risk)
- Abuse report history
- Clean, user-friendly interface

## Prerequisites

- Node.js (v14 or higher)
- AbuseIPDB API key ([Get one here](https://www.abuseipdb.com/api))

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
ABUSEIPDB_API_KEY=your_api_key_here
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

## API Endpoint

### POST /api/ip

Check an IP address for abuse reports and threat intelligence.

**Request Body:**
```json
{
  "ip": "8.8.8.8"
}
```

**Response:**
```json
{
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
}
```

## Dependencies

- **express** - Web server framework
- **axios** - HTTP client for API requests
- **dotenv** - Environment variable management

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- IP threat intelligence powered by [AbuseIPDB](https://www.abuseipdb.com/)
