require('dotenv').config();
const express = require('express');
const axios = require('axios');
const { RateLimiterMemory } = require('rate-limiter-flexible');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Rate limiter configuration
// General API limiter: 10 requests per minute per IP
const apiLimiter = new RateLimiterMemory({
  points: 10, // Number of requests
  duration: 60, // Per 60 seconds (1 minute)
  blockDuration: 60, // Block for 60 seconds if exceeded
});

// Strict limiter for external API calls: 5 requests per minute per IP
// This protects against quota exhaustion from external APIs
const strictLimiter = new RateLimiterMemory({
  points: 5, // Number of requests
  duration: 60, // Per 60 seconds
  blockDuration: 120, // Block for 2 minutes if exceeded
});

// Rate limiter middleware factory
const rateLimiterMiddleware = (limiter) => {
  return async (req, res, next) => {
    try {
      // Use IP address as key for rate limiting
      const key = req.ip || req.connection.remoteAddress;
      await limiter.consume(key);
      next();
    } catch (rejRes) {
      // Rate limit exceeded
      const secs = Math.round(rejRes.msBeforeNext / 1000) || 1;
      res.set('Retry-After', String(secs));
      res.status(429).json({
        error: 'Too many requests',
        message: `Rate limit exceeded. Please try again in ${secs} seconds.`,
        retryAfter: secs
      });
    }
  };
};

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

function isValidIP(ip) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

// VirusTotal Integration Functions
function normalizeVirusTotalIPData(data) {
  const attributes = data.attributes || {};
  const stats = attributes.last_analysis_stats || {};
  const totalScans = Object.values(stats).reduce((a, b) => a + b, 0);
  
  return {
    ipAddress: data.id || 'N/A',
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    totalScans: totalScans,
    detectionRate: totalScans > 0 ? `${stats.malicious}/${totalScans}` : '0/0',
    country: attributes.country || 'Unknown',
    asOwner: attributes.as_owner || 'Unknown',
    reputation: attributes.reputation || 0,
    threatLevel: getVirusTotalThreatLevel(stats.malicious, totalScans),
    lastAnalysisDate: attributes.last_analysis_date 
      ? new Date(attributes.last_analysis_date * 1000).toLocaleString() 
      : 'N/A',
    summary: generateVirusTotalSummary(stats, totalScans)
  };
}

function getVirusTotalThreatLevel(malicious, total) {
  if (total === 0) return 'Unknown';
  const percentage = (malicious / total) * 100;
  if (percentage >= 10) return 'High Risk';
  if (percentage >= 5) return 'Medium Risk';
  if (percentage > 0) return 'Low Risk';
  return 'Clean';
}

function generateVirusTotalSummary(stats, total) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  
  if (total === 0) {
    return 'No scan data available from VirusTotal.';
  }
  
  if (malicious === 0 && suspicious === 0) {
    return `Clean: 0 security vendors flagged this IP as malicious (${total} total).`;
  }
  
  return `Flagged: ${malicious} security vendor(s) flagged this as malicious, ${suspicious} as suspicious (${total} total).`;
}

app.post('/api/ip', rateLimiterMiddleware(strictLimiter), async (req, res) => {
  const { ip } = req.body;

  if (!ip) {
    return res.status(400).json({ error: 'An IP address is required' });
  }

  if (!isValidIP(ip)) {
    return res.status(400).json({ error: 'Invalid IP address format' });
  }

  try {
    // Fetch from both AbuseIPDB and VirusTotal
    const [abuseIPDBResponse, virusTotalResponse] = await Promise.allSettled([
      axios.get('https://api.abuseipdb.com/api/v2/check', {
        params: {
          ipAddress: ip,
          maxAgeInDays: 90
        },
        headers: {
          Key: process.env.ABUSEIPDB_API_KEY,
          Accept: 'application/json'
        }
      }),
      axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
        headers: {
          'x-apikey': process.env.VIRUSTOTAL_API_KEY
        }
      })
    ]);

    const result = {
      ip: ip,
      abuseipdb: null,
      virustotal: null
    };

    // Process AbuseIPDB data
    if (abuseIPDBResponse.status === 'fulfilled') {
      result.abuseipdb = normalizeAbuseIPData(abuseIPDBResponse.value.data.data);
    } else {
      console.error('AbuseIPDB Error:', abuseIPDBResponse.reason?.message);
      result.abuseipdb = { error: 'AbuseIPDB lookup failed' };
    }

    // Process VirusTotal data
    if (virusTotalResponse.status === 'fulfilled') {
      result.virustotal = normalizeVirusTotalIPData(virusTotalResponse.value.data.data);
    } else {
      console.error('VirusTotal Error:', virusTotalResponse.reason?.message);
      result.virustotal = { error: 'VirusTotal lookup failed' };
    }

    res.json(result);
  } catch (err) {
    console.error('API Error:', err.response?.data || err.message);
    
    if (err.response?.status === 429) {
      return res.status(429).json({ error: 'Rate limit exceeded. Please try again later.' });
    }
    
    if (err.response?.status === 401) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    res.status(500).json({ error: 'API request failed', details: err.message });
  }
});

// New VirusTotal-specific endpoints
app.post('/api/virustotal/domain', rateLimiterMiddleware(strictLimiter), async (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ error: 'A domain is required' });
  }

  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: {
        'x-apikey': process.env.VIRUSTOTAL_API_KEY
      }
    });

    const attributes = response.data.data.attributes || {};
    const stats = attributes.last_analysis_stats || {};
    const totalScans = Object.values(stats).reduce((a, b) => a + b, 0);

    res.json({
      domain: domain,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      totalScans: totalScans,
      detectionRate: totalScans > 0 ? `${stats.malicious}/${totalScans}` : '0/0',
      reputation: attributes.reputation || 0,
      categories: attributes.categories || {},
      lastAnalysisDate: attributes.last_analysis_date 
        ? new Date(attributes.last_analysis_date * 1000).toLocaleString() 
        : 'N/A'
    });
  } catch (err) {
    console.error('VirusTotal Domain API Error:', err.response?.data || err.message);
    res.status(err.response?.status || 500).json({ 
      error: 'VirusTotal domain lookup failed', 
      details: err.message 
    });
  }
});

app.post('/api/virustotal/url', rateLimiterMiddleware(strictLimiter), async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'A URL is required' });
  }

  try {
    // First, submit the URL for analysis
    const submitResponse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url: url }),
      {
        headers: {
          'x-apikey': process.env.VIRUSTOTAL_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const analysisId = submitResponse.data.data.id;

    // Wait a moment then get the analysis results
    await new Promise(resolve => setTimeout(resolve, 2000));

    const analysisResponse = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          'x-apikey': process.env.VIRUSTOTAL_API_KEY
        }
      }
    );

    const attributes = analysisResponse.data.data.attributes || {};
    const stats = attributes.stats || {};
    const totalScans = Object.values(stats).reduce((a, b) => a + b, 0);

    res.json({
      url: url,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      totalScans: totalScans,
      detectionRate: totalScans > 0 ? `${stats.malicious}/${totalScans}` : '0/0',
      status: attributes.status || 'queued'
    });
  } catch (err) {
    console.error('VirusTotal URL API Error:', err.response?.data || err.message);
    res.status(err.response?.status || 500).json({ 
      error: 'VirusTotal URL lookup failed', 
      details: err.message 
    });
  }
});

app.post('/api/virustotal/hash', rateLimiterMiddleware(strictLimiter), async (req, res) => {
  const { hash } = req.body;

  if (!hash) {
    return res.status(400).json({ error: 'A file hash is required' });
  }

  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: {
        'x-apikey': process.env.VIRUSTOTAL_API_KEY
      }
    });

    const attributes = response.data.data.attributes || {};
    const stats = attributes.last_analysis_stats || {};
    const totalScans = Object.values(stats).reduce((a, b) => a + b, 0);

    res.json({
      hash: hash,
      fileName: attributes.meaningful_name || attributes.names?.[0] || 'Unknown',
      fileType: attributes.type_description || 'Unknown',
      fileSize: attributes.size || 0,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      totalScans: totalScans,
      detectionRate: totalScans > 0 ? `${stats.malicious}/${totalScans}` : '0/0',
      lastAnalysisDate: attributes.last_analysis_date 
        ? new Date(attributes.last_analysis_date * 1000).toLocaleString() 
        : 'N/A'
    });
  } catch (err) {
    console.error('VirusTotal Hash API Error:', err.response?.data || err.message);
    res.status(err.response?.status || 500).json({ 
      error: 'VirusTotal file hash lookup failed', 
      details: err.message 
    });
  }
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
