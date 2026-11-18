require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getFirestore, FieldValue, Timestamp } = require('firebase-admin/firestore');
const { getMessaging } = require('firebase-admin/messaging');

// Initialize Firebase Admin safely using v14 modular APIs
if (!getApps().length) {
  let serviceAccount;
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  } else {
    serviceAccount = require('./serviceAccountKey.json');
  }

  initializeApp({
    credential: cert(serviceAccount)
  });
}

const db = getFirestore();
const messaging = getMessaging();

const app = express();
app.set('trust proxy', 1); // Extracts real client IP from Vercel's X-Forwarded-For header
app.use(cors());
app.use(express.json());

const INTERNAL_API_SECRET = process.env.INTERNAL_API_SECRET || 'dev-secret-change-in-prod';
const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const MAX_OTP_ATTEMPTS = 5;

function normalizePhone(phone) {
  return String(phone || '').replace(/\D/g, '');
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || req.ip || 'Unknown IP';
}

function hashOtp(otp, challengeId) {
  return crypto.createHash('sha256').update(`${challengeId}:${otp}`).digest('hex');
}

function requireInternalSecret(req, res, next) {
  const secret = req.headers['x-api-secret'];
  if (secret !== INTERNAL_API_SECRET) {
    return res.status(401).json({ success: false, error: 'Unauthorized API secret' });
  }
  next();
}

// Root & Health Check
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'NectaMail Phone-Only OTP Vault (Vercel)' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

/**
 * 1. BIND DEVICE TO PHONE NUMBER (Phone-only account, no email stored)
 */
app.post('/api/device/bind', async (req, res) => {
  try {
    const phoneNumber = normalizePhone(req.body.phoneNumber);
    const { fcmToken, publicKey, deviceName } = req.body;

    if (!phoneNumber || phoneNumber.length < 10) {
      return res.status(400).json({ success: false, error: 'Valid SIM phone number required' });
    }

    const deviceRef = db.collection('device_bindings').doc(phoneNumber);
    const existing = await deviceRef.get();

    const payload = {
      phoneNumber,
      fcmToken: fcmToken || null,
      publicKey: publicKey || null,
      deviceName: deviceName || 'Android Device',
      lastBoundIp: getClientIp(req),
      updatedAt: FieldValue.serverTimestamp()
    };

    if (!existing.exists) {
      payload.boundAt = FieldValue.serverTimestamp();
    }

    await deviceRef.set(payload, { merge: true });

    res.json({
      success: true,
      message: 'Phone number and device bound successfully',
      phoneNumber
    });
  } catch (err) {
    console.error('Bind Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * 2. REQUEST OTP (Stores OTP + Requester IP inside phone's otp_history + Sends FCM Push)
 */
app.post('/api/otp/request', requireInternalSecret, async (req, res) => {
  try {
    const phoneNumber = normalizePhone(req.body.phoneNumber);
    const requesterIp = req.body.requesterIp || getClientIp(req);
    const userAgent = req.body.userAgent || req.headers['user-agent'] || 'Unknown Client';

    if (!phoneNumber) {
      return res.status(400).json({ success: false, error: 'phoneNumber is required' });
    }

    const deviceRef = db.collection('device_bindings').doc(phoneNumber);
    const deviceSnap = await deviceRef.get();

    if (!deviceSnap.exists) {
      return res.status(404).json({
        success: false,
        error: 'Phone number not registered. Bind this SIM in NectaMail OTP Verifier first.'
      });
    }

    const deviceData = deviceSnap.data();
    const challengeId = crypto.randomUUID();
    const otp = String(crypto.randomInt(100000, 999999));
    const now = Date.now();
    const expiresAt = now + OTP_EXPIRY_MS;

    await deviceRef.collection('otp_history').doc(challengeId).set({
      challengeId,
      otpHash: hashOtp(otp, challengeId),
      codeDisplay: otp,
      requesterIp,
      userAgent,
      status: 'PENDING',
      attempts: 0,
      createdAt: Timestamp.fromMillis(now),
      expiresAt: Timestamp.fromMillis(expiresAt)
    });

    let pushStatus = 'SKIPPED_TEST_TOKEN';
    if (deviceData.fcmToken && !deviceData.fcmToken.startsWith('TEST_')) {
      try {
        await messaging.send({
          token: deviceData.fcmToken,
          data: {
            type: 'NECTAMAIL_OTP',
            challengeId,
            otp,
            requesterIp,
            expiresAt: String(expiresAt)
          },
          android: { priority: 'high' }
        });
        pushStatus = 'SENT';
      } catch (fcmErr) {
        console.error('FCM Send Error:', fcmErr.message);
        pushStatus = `FAILED: ${fcmErr.message}`;
      }
    }

    const responsePayload = {
      success: true,
      challengeId,
      requesterIp,
      expiresAt,
      pushStatus
    };

    if (process.env.ALLOW_TEST_DEBUG === 'true' && req.body.debug === true) {
      responsePayload.debugOtp = otp;
    }

    res.json(responsePayload);
  } catch (err) {
    console.error('OTP Request Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * 3. VERIFY OTP
 */
app.post('/api/otp/verify', requireInternalSecret, async (req, res) => {
  try {
    const phoneNumber = normalizePhone(req.body.phoneNumber);
    const { challengeId, otp } = req.body;

    if (!phoneNumber || !challengeId || !otp) {
      return res.status(400).json({ success: false, error: 'phoneNumber, challengeId, and otp are required' });
    }

    const historyRef = db
      .collection('device_bindings')
      .doc(phoneNumber)
      .collection('otp_history')
      .doc(challengeId);

    const snap = await historyRef.get();
    if (!snap.exists) {
      return res.status(404).json({ success: false, error: 'OTP challenge not found' });
    }

    const record = snap.data();

    if (record.status !== 'PENDING') {
      return res.status(400).json({ success: false, error: `OTP already ${record.status.toLowerCase()}` });
    }

    if (Date.now() > record.expiresAt.toMillis()) {
      await historyRef.update({ status: 'EXPIRED' });
      return res.status(400).json({ success: false, error: 'OTP has expired' });
    }

    if (record.attempts >= MAX_OTP_ATTEMPTS) {
      await historyRef.update({ status: 'LOCKED' });
      return res.status(429).json({ success: false, error: 'Too many wrong attempts. Request a new OTP.' });
    }

    const submittedHash = hashOtp(String(otp).trim(), challengeId);
    if (submittedHash !== record.otpHash) {
      await historyRef.update({ attempts: FieldValue.increment(1) });
      return res.status(400).json({
        success: false,
        error: 'Invalid OTP',
        remainingAttempts: MAX_OTP_ATTEMPTS - (record.attempts + 1)
      });
    }

    await historyRef.update({
      status: 'VERIFIED',
      verifiedAt: FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      verified: true,
      requesterIp: record.requesterIp
    });
  } catch (err) {
    console.error('Verify Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * 4. GET OTP INBOX & HISTORICAL IP AUDIT LOG
 */
app.get('/api/otp/history/:phoneNumber', async (req, res) => {
  try {
    const phoneNumber = normalizePhone(req.params.phoneNumber);
    const deviceRef = db.collection('device_bindings').doc(phoneNumber);
    const deviceSnap = await deviceRef.get();

    if (!deviceSnap.exists) {
      return res.status(404).json({ success: false, error: 'Phone number not bound' });
    }

    const historySnap = await deviceRef
      .collection('otp_history')
      .orderBy('createdAt', 'desc')
      .limit(25)
      .get();

    const now = Date.now();
    const items = [];

    for (const doc of historySnap.docs) {
      const data = doc.data();
      let status = data.status;

      if (status === 'PENDING' && now > data.expiresAt.toMillis()) {
        status = 'EXPIRED';
        doc.ref.update({ status: 'EXPIRED' }).catch(() => {});
      }

      items.push({
        challengeId: data.challengeId,
        otp: data.codeDisplay,
        requesterIp: data.requesterIp,
        userAgent: data.userAgent,
        status,
        createdAt: data.createdAt?.toMillis() || null,
        expiresAt: data.expiresAt?.toMillis() || null
      });
    }

    res.json({
      success: true,
      phoneNumber,
      device: {
        deviceName: deviceSnap.data().deviceName,
        lastBoundIp: deviceSnap.data().lastBoundIp
      },
      history: items
    });
  } catch (err) {
    console.error('History Fetch Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Local development listener (ignored by Vercel serverless runtime)
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`NectaMail OTP Vault running on port ${PORT}`));
}

module.exports = app;
