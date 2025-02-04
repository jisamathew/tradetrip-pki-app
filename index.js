const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');
require('dotenv').config();

const app = express();
const PORT = 4000;
const uri = process.env.MONGO_URI;

const client = new MongoClient(uri);
let db;

// app.use(cors());
app.use(cors({
  origin: ['http://localhost:3000', 'https://tradetrip-mongo-connect.web.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Handle preflight requests
app.options('*', (req, res) => {
  res.header("Access-Control-Allow-Origin", "https://tradetrip-mongo-connect.web.app");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Credentials", "true");
  res.sendStatus(200);
});

app.use(express.json());

async function connectToDatabase() {
  try {
    await client.connect();
    db = client.db('tradetrip_PKI');
    await db.createCollection('pki_certificates');
    console.log('PKI Server: Connected to MongoDB');
  } catch (error) {
    console.error('PKI Server MongoDB connection error:', error);
    process.exit(1);
  }
}

function generateKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
}

function generateCertificate(publicKey, userId, email) {
  return {
    serialNumber: crypto.randomBytes(16).toString('hex'),
    userId: userId,
    email: email,
    publicKey: publicKey,
    issuer: 'COO Certifying Authority',
    validFrom: new Date(),
    validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    signature: crypto.randomBytes(32).toString('hex')
  };
}

app.post('/generate-certificate', async (req, res) => {
  try {
    const { userId, email } = req.body;
    console.log('Generating certificate for:', { userId, email });

    if (!userId || !email) {
      return res.status(400).json({ error: 'User ID and email are required' });
    }

    const keyPair = generateKeyPair();
    const certificate = generateCertificate(keyPair.publicKey, userId, email);
    console.log(certificate)

    await db.collection('pki_certificates').insertOne({
      ...certificate,
      createdAt: new Date()
    });

    console.log('Certificate generated successfully');
    res.json({
      message: 'Certificate generated successfully',
      certificate,
      privateKey: keyPair.privateKey
    });
    console.log(keyPair.privateKey)
  } catch (error) {
    console.error('Certificate generation error:', error);
    res.status(500).json({ error: 'Certificate generation failed' });
  }
});

app.post('/verify-certificate', async (req, res) => {
  try {
    const { userId, email } = req.body;

    // Basic input validation
    if (!userId || !email) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const certificate = await db.collection('pki_certificates').findOne({
      userId,
      email
    });

    if (!certificate) {
      return res.status(404).json({ error: 'Certificate not found' });
    }

    if (new Date() > new Date(certificate.validTo)) {
      return res.status(401).json({ error: 'Certificate expired' });
    }

    res.json({
      valid: true,
      certificate
    });
  } catch (error) {
    if (error.name === 'MongoError') { 
      console.error('Database error:', error);
      return res.status(500).json({ error: 'Database error' }); 
    } else {
      console.error('Unexpected error:', error);
      return res.status(500).json({ error: 'An unexpected error occurred' }); 
    }
  }
});
app.post('/get-public-key', async (req, res) => {
  try {
      const { userId } = req.body;

      if (!userId) {
          return res.status(400).json({ error: 'User ID is required' });
      }

      const user = await db.collection('pki_certificates').findOne({ userId });

      if (!user || !user.publicKey) {
          return res.status(404).json({ error: 'Public key not found for the user' });
      }

      res.json({ publicKey: user.publicKey });
  } catch (error) {
      console.error('Error fetching public key:', error);
      res.status(500).json({ error: 'Failed to fetch public key' });
  }
});

connectToDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`PKI Server is running on http://localhost:${PORT}`);
  });
}).catch(console.error);