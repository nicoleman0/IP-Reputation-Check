require('dotenv').config();
const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

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

    res.json(response.data.data);
  } catch (err) {
    res.status(500).json({ error: 'API request failed' });
  }
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
