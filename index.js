require('dotenv').config();
const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(express.static('public'));

function normalizeAbuseIPData(data) {
  return {
    ipAddress: data.ipAddress || 'N/A',
    isPublic: data.isPublic || false,
    ipVersion: data.ipVersion || 'N/A',
    isWhitelisted: data.isWhitelisted || false,
    abuseConfidenceScore: data.abuseConfidenceScore || 0,
    countryCode: data.countryCode || 'Unknown',
    countryName: data.countryName || 'Unknown',
    usageType: data.usageType || 'Unknown',
    isp: data.isp || 'Unknown',
    domain: data.domain || 'Unknown',
    hostnames: data.hostnames && data.hostnames.length > 0 
      ? data.hostnames 
      : ['No hostnames available'],
    totalReports: data.totalReports || 0,
    numDistinctUsers: data.numDistinctUsers || 0,
    lastReportedAt: data.lastReportedAt 
      ? new Date(data.lastReportedAt).toLocaleString() 
      : 'Never reported',
    threatLevel: getThreatLevel(data.abuseConfidenceScore),
    summary: generateSummary(data)
  };
}

function getThreatLevel(score) {
  if (score >= 75) return 'High Risk';
  if (score >= 50) return 'Medium Risk';
  if (score >= 25) return 'Low Risk';
  return 'Minimal Risk';
}

function generateSummary(data) {
  const score = data.abuseConfidenceScore || 0;
  const reports = data.totalReports || 0;
  const country = data.countryName || 'Unknown';
  
  if (reports === 0) {
    return `This IP from ${country} has no abuse reports.`;
  }
  
  return `This IP from ${country} has ${reports} abuse report(s) with a ${score}% confidence score.`;
}

app.post('/api/ip', async (req, res) => {
  const { ip } = req.body;

  if (!ip) {
    return res.status(400).json({ error: 'An IP address is required' });
  }

  try {
    const response = await axios.get(
      'https://api.abuseipdb.com/api/v2/check',
      {
        params: {
          ipAddress: ip,
          maxAgeInDays: 90
        },
        headers: {
          Key: process.env.ABUSEIPDB_API_KEY,
          Accept: 'application/json'
        }
      }
    );

    const normalizedData = normalizeAbuseIPData(response.data.data);
    res.json(normalizedData);
  } catch (err) {
    res.status(500).json({ error: 'API request failed' });
  }
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
