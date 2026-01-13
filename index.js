require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');

const app = express();
const PORT = process.env.PORT || 3000;

const STRICT_PARAMS = (() => {
  const raw = String(process.env.STRICT_PARAMS || '').trim().toLowerCase();
  return ['true', '1', 'yes', 'y'].includes(raw);
})();

const API_KEY = process.env.API_KEY || 'test-api-key-123';

const TTL_MINUTES = Number(process.env.TTL_MINUTES || 10);
const TTL_MS = TTL_MINUTES * 60 * 1000;

const ACCESS_TOKEN_TTL_MINUTES = Number(process.env.ACCESS_TOKEN_TTL_MINUTES || 30);
const ACCESS_TOKEN_TTL_MS = ACCESS_TOKEN_TTL_MINUTES * 60 * 1000;

const REFRESH_TOKEN_TTL_DAYS = Number(process.env.REFRESH_TOKEN_TTL_DAYS || 7);
const REFRESH_TOKEN_TTL_MS = REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000;

const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 5);
const OTP_TTL_MS = OTP_TTL_MINUTES * 60 * 1000;
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || 3);

const MAX_LOGIN_ATTEMPTS = Number(process.env.MAX_LOGIN_ATTEMPTS || 3);
const LOGIN_LOCK_MINUTES = Number(process.env.LOGIN_LOCK_MINUTES || 15);
const LOGIN_LOCK_MS = LOGIN_LOCK_MINUTES * 60 * 1000;

const ASYNC_TRANSFER_DELAY_SECONDS = Number(process.env.ASYNC_TRANSFER_DELAY_SECONDS || 6);
const ASYNC_TRANSFER_DELAY_MS = ASYNC_TRANSFER_DELAY_SECONDS * 1000;

app.use(cors());
app.use(express.json());

// ----------------------- In-memory "DB" -----------------------
const now = () => Date.now();

// Customers (login users) + role support for Admin APIs
// NOTE: Roles are for teaching role-based security validation.
const customers = [
  { customerId: 1001, username: 'mahesh', password: 'Password@123', fullName: 'Mahesh Upadhyay', mobile: '9999999999', role: 'ADMIN' },
  { customerId: 1002, username: 'riya', password: 'Password@123', fullName: 'Riya Sharma', mobile: '8888888888', role: 'CUSTOMER' },
];

const accounts = [
  { accountId: 20001, customerId: 1001, type: 'SAVINGS', currency: 'INR', balance: 250000.50, status: 'ACTIVE' },
  { accountId: 20002, customerId: 1001, type: 'CURRENT', currency: 'INR', balance: 50000.00, status: 'ACTIVE' },
  { accountId: 20003, customerId: 1002, type: 'SAVINGS', currency: 'INR', balance: 12500.00, status: 'ACTIVE' },
];

const beneficiaries = [
  { beneficiaryId: 30001, customerId: 1001, name: 'Ramesh', bankName: 'HDFC', ifsc: 'HDFC0000123', accountNumber: '12345678901', status: 'ACTIVE' },
  { beneficiaryId: 30002, customerId: 1001, name: 'Neha', bankName: 'ICICI', ifsc: 'ICIC0000456', accountNumber: '10987654321', status: 'ACTIVE' },
];

const transactions = []; // {txnId, customerId, fromAccountId, toBeneficiaryId?, amount, currency, narration, type, status, createdAt, mode, referenceId?}

const cards = [
  { cardId: 40001, customerId: 1001, last4: '1234', type: 'DEBIT', status: 'ACTIVE', domesticEnabled: true, onlineEnabled: true, atmEnabled: true, limitPerDay: 50000 },
  { cardId: 40002, customerId: 1002, last4: '5678', type: 'DEBIT', status: 'ACTIVE', domesticEnabled: true, onlineEnabled: true, atmEnabled: true, limitPerDay: 20000 },
];

const loans = [
  { loanId: 50001, customerId: 1001, type: 'HOME_LOAN', principal: 2500000, interestRate: 8.5, tenureMonths: 240, outstanding: 2350000, status: 'ACTIVE' },
];

// TTL overrides (freeze etc.)
const overrides = new Map(); // key -> { expiresAt, data }
function pruneOverrides(){
  const t = now();
  for (const [k,v] of overrides.entries()){
    if (v.expiresAt <= t) overrides.delete(k);
  }
}

// Login attempt tracking + lock
const loginAttempts = new Map(); // username -> { count, lockedUntil }
function isLocked(username){
  const rec = loginAttempts.get(username);
  return rec?.lockedUntil && rec.lockedUntil > now();
}

// OTP store
const otpSessions = new Map(); // otpSessionId -> { customerId, otp, createdAt, expiresAt, attemptsLeft }
function pruneOtp(){
  const t = now();
  for (const [sid,obj] of otpSessions.entries()){
    if (obj.expiresAt <= t) otpSessions.delete(sid);
  }
}

// Tokens
const accessTokens = new Map();  // accessToken -> { customerId, createdAt, expiresAt }
const refreshTokens = new Map(); // refreshToken -> { customerId, createdAt, expiresAt }

function pruneTokens(){
  const t = now();
  for (const [k,v] of accessTokens.entries()) if (v.expiresAt <= t) accessTokens.delete(k);
  for (const [k,v] of refreshTokens.entries()) if (v.expiresAt <= t) refreshTokens.delete(k);
}

// ----------------------- Helpers -----------------------
function badRequest(res, message, details){
  return res.status(400).json({ status: 400, error: 'Bad Request', message, ...(details?{details}:{}) });
}
function unauthorized(res, message){
  return res.status(401).json({ status: 401, error: 'Unauthorized', message });
}
function forbidden(res, message){
  return res.status(403).json({ status: 403, error: 'Forbidden', message });
}
function notFound(res, message){
  return res.status(404).json({ status: 404, error: 'Not Found', message });
}
function methodNotAllowed(res, allow){
  res.set('Allow', allow.join(', '));
  return res.status(405).json({ status: 405, error: 'Method Not Allowed', message: `Allowed methods: ${allow.join(', ')}` });
}
function unsupportedMediaType(res){
  return res.status(415).json({ status: 415, error: 'Unsupported Media Type', message: 'Content-Type must be application/json' });
}
function unprocessable(res, message, details){
  return res.status(422).json({ status: 422, error: 'Unprocessable Entity', message, ...(details?{details}:{}) });
}
function tooManyRequests(res, retryAfterSec){
  res.set('Retry-After', String(retryAfterSec));
  return res.status(429).json({ status: 429, error: 'Too Many Requests', message: 'Rate limit exceeded', retryAfterSeconds: retryAfterSec });
}
function validateKnownParams(query, knownKeys, res){
  if (!STRICT_PARAMS) return true;
  const unknown = Object.keys(query).filter(k=>!knownKeys.includes(k));
  if (unknown.length){
    badRequest(res,'Unsupported query parameter(s)', { unsupported: unknown });
    return false;
  }
  return true;
}
function requireJson(req,res,next){
  const ct = req.headers['content-type']||'';
  if (!ct.toLowerCase().includes('application/json')) return unsupportedMediaType(res);
  next();
}
function nextIdFrom(prefix){
  return Number(prefix + String(Math.floor(100000 + Math.random()*899999)));
}
function round2(n){ return Math.round(n*100)/100; }
function isNonEmptyString(v){ return typeof v==='string' && v.trim().length>0; }
function maskMobile(m){ return m ? m.slice(0,2)+'XXXXXX'+m.slice(-2) : ''; }

function isValidIFSC(ifsc){
  return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(String(ifsc||'').trim().toUpperCase());
}
function isValidAccountNumber(n){
  const s = String(n||'').trim();
  return /^[0-9]{9,18}$/.test(s);
}

// --- ETag / 304 helpers ---
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
function computeETag(payload){
  return `W/"${md5(payload)}"`;
}
function sendWithETag(req, res, data){
  // data can be any JSON serializable structure
  const payload = JSON.stringify(data);
  const etag = computeETag(payload);
  const inm = req.headers['if-none-match'];
  res.set('ETag', etag);
  if (inm && inm === etag) return res.status(304).end();
  return res.status(200).json(data);
}

// ----------------------- Security: API Key -----------------------
function apiKeyRequired(req,res,next){
  const key = req.headers['x-api-key'];
  if (!key || key !== API_KEY) return unauthorized(res,'Invalid or missing API key');
  next();
}

// ----------------------- Security: Access Token -----------------------
function generateAccessToken(){
  return crypto.randomBytes(32).toString('hex');
}
function generateRefreshToken(){
  return crypto.randomBytes(48).toString('hex');
}
function accessTokenRequired(req,res,next){
  pruneTokens();
  const auth = req.headers['authorization'] || '';
  const bearerToken = auth.toLowerCase().startsWith('bearer ')
    ? auth.slice(7).trim()
    : null;
  const token = bearerToken || req.headers['x-access-token'];
  if (!token) return unauthorized(res,'Invalid or missing access token');
  const rec = accessTokens.get(token);
  if (!rec) return unauthorized(res,'Invalid or expired access token');
  req.customerId = rec.customerId;
  req.accessToken = token;

  const cust = customers.find(c => c.customerId === rec.customerId);
  req.customerRole = cust?.role || 'CUSTOMER';

  next();
}

// --- Role based check (403) ---
function requireRole(roles = []) {
  return (req, res, next) => {
    if (!roles.includes(req.customerRole)) {
      return forbidden(res, `Access denied. Required role(s): ${roles.join(', ')}`);
    }
    next();
  };
}

// ----------------------- Swagger -----------------------
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Advanced Mock Banking API',
      version: '3.0.0',
      description: 'Advanced mock Banking API without DB: password login + OTP, account lock, refresh token, async transfers, validations + 204/304/403/405 support.'
    },
    servers: [
  { url: 'http://localhost:3001', description: 'Local' },
  { url: 'https://automatedscript-banking-api.onrender.com', description: 'Production (Automated Script)' }
],
    components: {
      securitySchemes: {
        ApiKeyAuth: { type: 'apiKey', in: 'header', name: 'x-api-key' },
        AccessTokenAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'Token' }
      }
    }
  },
  apis: ['./index.js']
};
const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ============================================================
// =========================== APIs ===========================
// ============================================================

// ----------------------- Auth APIs -----------------------

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Step 1 Login (password) -> returns OTP session
 *     tags: [Auth]
 *     security: [{ ApiKeyAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [username, password]
 *             properties:
 *               username: { type: string, example: "mahesh" }
 *               password: { type: string, example: "Password@123" }
 *     responses:
 *       200: { description: OTP session created }
 *       400: { description: Bad request }
 *       401: { description: Unauthorized / locked }
 *       415: { description: Unsupported media type }
 */
app.post('/auth/login', requireJson, apiKeyRequired, (req,res)=>{
  pruneOtp();
  const { username, password } = req.body || {};
  if (!isNonEmptyString(username)) return badRequest(res,'Field "username" is required');
  if (!isNonEmptyString(password)) return badRequest(res,'Field "password" is required');

  const uname = username.trim();
  if (isLocked(uname)){
    const rec = loginAttempts.get(uname);
    return unauthorized(res, `Account locked. Try after ${new Date(rec.lockedUntil).toISOString()}`);
  }

  const user = customers.find(c => c.username === uname);
  if (!user || user.password !== password){
    const rec = loginAttempts.get(uname) || { count:0, lockedUntil:0 };
    rec.count += 1;
    if (rec.count >= MAX_LOGIN_ATTEMPTS){
      rec.lockedUntil = now() + LOGIN_LOCK_MS;
      rec.count = 0;
      loginAttempts.set(uname, rec);
      return unauthorized(res, `Account locked for ${LOGIN_LOCK_MINUTES} minutes`);
    }
    loginAttempts.set(uname, rec);
    return unauthorized(res,'Invalid credentials');
  }

  loginAttempts.delete(uname);

  const otp = String(Math.floor(100000 + Math.random()*900000));
  const otpSessionId = crypto.randomBytes(16).toString('hex');
  const createdAt = now();
  const expiresAt = createdAt + OTP_TTL_MS;

  otpSessions.set(otpSessionId, { customerId:user.customerId, otp, createdAt, expiresAt, attemptsLeft: OTP_MAX_ATTEMPTS });

  return res.status(200).json({
    status:200,
    message:'OTP sent to registered mobile',
    otpSessionId,
    otpTtlMinutes: OTP_TTL_MINUTES,
    maskedMobile: maskMobile(user.mobile),
    demoOtp: otp
  });
});

app.all('/auth/login', (req,res) => methodNotAllowed(res, ['POST']));

/**
 * @swagger
 * /auth/verify-otp:
 *   post:
 *     summary: Step 2 Verify OTP -> returns access + refresh tokens
 *     tags: [Auth]
 *     security: [{ ApiKeyAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [otpSessionId, otp]
 *             properties:
 *               otpSessionId: { type: string }
 *               otp: { type: string, example: "123456" }
 *     responses:
 *       200: { description: Token generated }
 *       400: { description: Bad request }
 *       401: { description: Unauthorized }
 *       415: { description: Unsupported media type }
 */
app.post('/auth/verify-otp', requireJson, apiKeyRequired, (req,res)=>{
  pruneOtp(); pruneTokens();
  const { otpSessionId, otp } = req.body || {};
  if (!isNonEmptyString(otpSessionId)) return badRequest(res,'Field "otpSessionId" is required');
  if (!isNonEmptyString(otp)) return badRequest(res,'Field "otp" is required');

  const sess = otpSessions.get(otpSessionId.trim());
  if (!sess) return unauthorized(res,'Invalid or expired OTP session');
  if (sess.attemptsLeft <= 0){
    otpSessions.delete(otpSessionId.trim());
    return unauthorized(res,'OTP attempts exceeded');
  }
  if (String(otp).trim() !== sess.otp){
    sess.attemptsLeft -= 1;
    otpSessions.set(otpSessionId.trim(), sess);
    return unauthorized(res, `Invalid OTP. Attempts left: ${sess.attemptsLeft}`);
  }

  otpSessions.delete(otpSessionId.trim());

  const accessToken = generateAccessToken();
  const refreshToken = generateRefreshToken();
  const createdAt = now();

  accessTokens.set(accessToken, { customerId:sess.customerId, createdAt, expiresAt: createdAt + ACCESS_TOKEN_TTL_MS });
  refreshTokens.set(refreshToken, { customerId:sess.customerId, createdAt, expiresAt: createdAt + REFRESH_TOKEN_TTL_MS });

  const cust = customers.find(c=>c.customerId===sess.customerId);

  return res.status(200).json({
    status:200,
    message:'Login successful',
    customerId: sess.customerId,
    fullName: cust?.fullName,
    role: cust?.role,
    accessToken,
    refreshToken,
    tokenType:'Bearer',
    accessTokenTtlMinutes: ACCESS_TOKEN_TTL_MINUTES,
    refreshTokenTtlDays: REFRESH_TOKEN_TTL_DAYS
  });
});

app.all('/auth/verify-otp', (req,res) => methodNotAllowed(res, ['POST']));

/**
 * @swagger
 * /auth/refresh-token:
 *   post:
 *     summary: Refresh access token using refresh token
 *     tags: [Auth]
 *     security: [{ ApiKeyAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [refreshToken]
 *             properties:
 *               refreshToken: { type: string }
 *     responses:
 *       200: { description: New access token }
 *       400: { description: Bad request }
 *       401: { description: Unauthorized }
 *       415: { description: Unsupported media type }
 */
app.post('/auth/refresh-token', requireJson, apiKeyRequired, (req,res)=>{
  pruneTokens();
  const { refreshToken } = req.body || {};
  if (!isNonEmptyString(refreshToken)) return badRequest(res,'Field "refreshToken" is required');

  const rec = refreshTokens.get(refreshToken.trim());
  if (!rec) return unauthorized(res,'Invalid or expired refresh token');

  const newAccessToken = generateAccessToken();
  const createdAt = now();
  accessTokens.set(newAccessToken, { customerId: rec.customerId, createdAt, expiresAt: createdAt + ACCESS_TOKEN_TTL_MS });

  return res.status(200).json({
    status:200,
    message:'Access token refreshed',
    accessToken: newAccessToken,
    tokenType:'Bearer',
    ttlMinutes: ACCESS_TOKEN_TTL_MINUTES
  });
});
app.all('/auth/refresh-token', (req,res) => methodNotAllowed(res, ['POST']));

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     summary: Logout (invalidate access token)
 *     tags: [Auth]
 *     security: [{ AccessTokenAuth: [] }]
 *     responses:
 *       200: { description: Logged out }
 *       401: { description: Unauthorized }
 */
app.post('/auth/logout', accessTokenRequired, (req,res)=>{
  accessTokens.delete(req.accessToken);
  return res.status(200).json({ status:200, message:'Logout successful' });
});
app.all('/auth/logout', (req,res) => methodNotAllowed(res, ['POST']));

// ----------------------- Customer -----------------------
/**
 * @swagger
 * /customer/profile:
 *   get:
 *     summary: Get customer profile
 *     tags: [Customer]
 *     security: [{ AccessTokenAuth: [] }]
 *     responses:
 *       200: { description: Profile returned }
 *       401: { description: Unauthorized }
 */
app.get('/customer/profile', accessTokenRequired, (req,res)=>{
  const cust = customers.find(c=>c.customerId===req.customerId);
  return res.status(200).json({
    status:200,
    data: { customerId: cust.customerId, fullName: cust.fullName, mobile: cust.mobile, role: cust.role }
  });
});
app.all('/customer/profile', (req,res) => methodNotAllowed(res, ['GET']));

// ----------------------- Accounts -----------------------
/**
 * @swagger
 * /accounts:
 *   get:
 *     summary: Get all accounts for logged-in customer
 *     description: Supports ETag caching. If-None-Match header can return 304.
 *     tags: [Accounts]
 *     security: [{ AccessTokenAuth: [] }]
 *     responses:
 *       200: { description: Accounts list }
 *       304: { description: Not Modified (ETag matched) }
 *       401: { description: Unauthorized }
 */
app.get('/accounts', accessTokenRequired, (req,res)=>{
  pruneOverrides();
  const list = accounts
    .filter(a=>a.customerId===req.customerId)
    .map(a=>{
      const ov = overrides.get(`account:${a.accountId}`);
      return ov?.data ? { ...a, ...ov.data } : a;
    });

  return sendWithETag(req, res, { status:200, count:list.length, data:list });
});
app.all('/accounts', (req,res) => methodNotAllowed(res, ['GET']));

/**
 * @swagger
 * /accounts/{accountId}/balance:
 *   get:
 *     summary: Get account balance
 *     tags: [Accounts]
 *     security: [{ AccessTokenAuth: [] }]
 *     parameters:
 *       - in: path
 *         name: accountId
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200: { description: Balance returned }
 *       400: { description: Bad request }
 *       401: { description: Unauthorized }
 *       404: { description: Account not found }
 */
app.get('/accounts/:accountId/balance', accessTokenRequired, (req,res)=>{
  const id = Number(req.params.accountId);
  if (!Number.isInteger(id) || id<=0) return badRequest(res,'Route parameter "accountId" must be a positive integer');
  const acc = accounts.find(a=>a.accountId===id && a.customerId===req.customerId);
  if (!acc) return notFound(res,'Account not found');
  return res.status(200).json({ status:200, data:{ accountId:acc.accountId, balance:acc.balance, currency:acc.currency, status:acc.status }});
});
app.all('/accounts/:accountId/balance', (req,res) => methodNotAllowed(res, ['GET']));

/**
 * @swagger
 * /accounts/{accountId}/freeze:
 *   post:
 *     summary: Freeze account temporarily (TTL demo)
 *     tags: [Accounts]
 *     security: [{ AccessTokenAuth: [] }]
 *     parameters:
 *       - in: path
 *         name: accountId
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200: { description: Account frozen temporarily }
 *       400: { description: Bad request }
 *       401: { description: Unauthorized }
 *       404: { description: Account not found }
 */
app.post('/accounts/:accountId/freeze', accessTokenRequired, (req,res)=>{
  const id = Number(req.params.accountId);
  if (!Number.isInteger(id) || id<=0) return badRequest(res,'Route parameter "accountId" must be a positive integer');
  const acc = accounts.find(a=>a.accountId===id && a.customerId===req.customerId);
  if (!acc) return notFound(res,'Account not found');

  const expiresAt = now()+TTL_MS;
  overrides.set(`account:${id}`, { expiresAt, data: { status:'FROZEN' }});
  setTimeout(()=>overrides.delete(`account:${id}`), TTL_MS);

  return res.status(200).json({ status:200, message:'Account frozen temporarily', ttlMinutes:TTL_MINUTES, expiresAt, data:{ accountId:id }});
});
app.all('/accounts/:accountId/freeze', (req,res) => methodNotAllowed(res, ['POST']));

// ----------------------- Beneficiaries -----------------------
/**
 * @swagger
 * /beneficiaries:
 *   get:
 *     summary: Get all beneficiaries
 *     tags: [Beneficiaries]
 *     security: [{ AccessTokenAuth: [] }]
 *     responses:
 *       200: { description: Beneficiaries list }
 *       401: { description: Unauthorized }
 */
app.get('/beneficiaries', accessTokenRequired, (req,res)=>{
  const list = beneficiaries.filter(b=>b.customerId===req.customerId);
  return res.status(200).json({ status:200, count:list.length, data:list });
});

/**
 * @swagger
 * /beneficiaries:
 *   post:
 *     summary: Add beneficiary
 *     tags: [Beneficiaries]
 *     security: [{ AccessTokenAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, bankName, ifsc, accountNumber]
 *             properties:
 *               name: { type: string, example: "Amit" }
 *               bankName: { type: string, example: "SBI" }
 *               ifsc: { type: string, example: "SBIN0000123" }
 *               accountNumber: { type: string, example: "123456789012" }
 *     responses:
 *       201: { description: Beneficiary created }
 *       400: { description: Validation error }
 *       401: { description: Unauthorized }
 *       415: { description: Unsupported media type }
 *       422: { description: Beneficiary already exists }
 */
app.post('/beneficiaries', requireJson, accessTokenRequired, (req,res)=>{
  const { name, bankName, ifsc, accountNumber } = req.body || {};
  if (!isNonEmptyString(name)) return badRequest(res,'Field "name" is required');
  if (!isNonEmptyString(bankName)) return badRequest(res,'Field "bankName" is required');
  if (!isNonEmptyString(ifsc) || !isValidIFSC(ifsc)) return badRequest(res,'Field "ifsc" is invalid. Format: 4 letters + 0 + 6 alphanumeric');
  if (!isNonEmptyString(accountNumber) || !isValidAccountNumber(accountNumber)) return badRequest(res,'Field "accountNumber" must be 9-18 digits');

  const exists = beneficiaries.some(b=>b.customerId===req.customerId && b.accountNumber===String(accountNumber).trim());
  if (exists) return unprocessable(res,'Beneficiary already exists');

  const beneficiaryId = nextIdFrom('30');
  const b = { beneficiaryId, customerId:req.customerId, name:name.trim(), bankName:bankName.trim(), ifsc:String(ifsc).trim().toUpperCase(), accountNumber:String(accountNumber).trim(), status:'ACTIVE' };
  beneficiaries.push(b);

  // 201 + Location header
  res.set('Location', `/beneficiaries/${beneficiaryId}`);
  return res.status(201).json({ status:201, message:'Beneficiary added', data:b });
});

/**
 * @swagger
 * /beneficiaries/{beneficiaryId}:
 *   delete:
 *     summary: Delete beneficiary (204 No Content)
 *     tags: [Beneficiaries]
 *     security: [{ AccessTokenAuth: [] }]
 *     parameters:
 *       - in: path
 *         name: beneficiaryId
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       204: { description: Deleted successfully (no response body) }
 *       400: { description: Bad request }
 *       401: { description: Unauthorized }
 *       404: { description: Not found }
 */
app.delete('/beneficiaries/:beneficiaryId', accessTokenRequired, (req,res)=>{
  const id = Number(req.params.beneficiaryId);
  if (!Number.isInteger(id) || id<=0) return badRequest(res,'Route parameter "beneficiaryId" must be a positive integer');
  const idx = beneficiaries.findIndex(b=>b.beneficiaryId===id && b.customerId===req.customerId);
  if (idx===-1) return notFound(res,'Beneficiary not found');
  beneficiaries.splice(idx,1);

  // ✅ 204 No Content
  return res.status(204).end();
});

// 405 handling for /beneficiaries
app.all('/beneficiaries', (req,res) => methodNotAllowed(res, ['GET','POST']));
app.all('/beneficiaries/:beneficiaryId', (req,res) => methodNotAllowed(res, ['DELETE']));

// ----------------------- Transfers -----------------------
function getModeLimits(mode){
  const m = String(mode||'').toUpperCase();
  if (m === 'IMPS') return { min: 1, max: 200000, eta: 'Instant' };
  if (m === 'NEFT') return { min: 1, max: 1000000, eta: '2 hours' };
  if (m === 'RTGS') return { min: 200000, max: 5000000, eta: 'Same day' };
  return null;
}

/**
 * @swagger
 * /transfer/fund:
 *   post:
 *     summary: Fund transfer to beneficiary (async PENDING->SUCCESS)
 *     tags: [Transfers]
 *     security: [{ AccessTokenAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [fromAccountId, toBeneficiaryId, amount, mode]
 *             properties:
 *               fromAccountId: { type: integer, example: 20001 }
 *               toBeneficiaryId: { type: integer, example: 30001 }
 *               amount: { type: number, example: 1500 }
 *               mode:
 *                 type: string
 *                 enum: [IMPS, NEFT, RTGS]
 *                 example: IMPS
 *               narration: { type: string, example: "Rent payment" }
 *     responses:
 *       202: { description: Transfer accepted (PENDING) }
 *       400: { description: Validation error }
 *       401: { description: Unauthorized }
 *       404: { description: Account/beneficiary not found }
 *       415: { description: Unsupported media type }
 *       422: { description: Insufficient balance or invalid mode limit }
 */
app.post('/transfer/fund', requireJson, accessTokenRequired, (req,res)=>{
  const { fromAccountId, toBeneficiaryId, amount, narration, mode } = req.body || {};
  const fromId = Number(fromAccountId);
  const benId = Number(toBeneficiaryId);
  const amt = Number(amount);

  if (!Number.isInteger(fromId) || fromId<=0) return badRequest(res,'Field "fromAccountId" must be a positive integer');
  if (!Number.isInteger(benId) || benId<=0) return badRequest(res,'Field "toBeneficiaryId" must be a positive integer');
  if (!Number.isFinite(amt) || amt<=0) return badRequest(res,'Field "amount" must be a positive number');

  const limits = getModeLimits(mode);
  if (!limits) return badRequest(res,'Field "mode" must be one of IMPS, NEFT, RTGS');

  if (amt < limits.min || amt > limits.max){
    return unprocessable(res, `Amount out of allowed limit for ${String(mode).toUpperCase()}`, { limit: limits });
  }

  pruneOverrides();
  const from = accounts.find(a=>a.accountId===fromId && a.customerId===req.customerId);
  if (!from) return notFound(res,'From account not found');

  const status = overrides.get(`account:${fromId}`)?.data?.status ?? from.status;
  if (status !== 'ACTIVE') return unprocessable(res,'Account is not ACTIVE');

  const ben = beneficiaries.find(b=>b.beneficiaryId===benId && b.customerId===req.customerId);
  if (!ben) return notFound(res,'Beneficiary not found');

  if (from.balance < amt) return unprocessable(res,'Insufficient balance');

  from.balance = round2(from.balance - amt);

  const txnId = nextIdFrom('70');
  const referenceId = crypto.randomBytes(10).toString('hex').toUpperCase();
  const txn = {
    txnId,
    referenceId,
    customerId:req.customerId,
    fromAccountId:fromId,
    toBeneficiaryId:benId,
    toAccountNumber:ben.accountNumber,
    amount:round2(amt),
    currency:from.currency,
    narration: narration ? String(narration).trim() : '',
    type:'FUND_TRANSFER',
    mode: String(mode).toUpperCase(),
    status:'PENDING',
    createdAt: now()
  };
  transactions.push(txn);

  setTimeout(()=>{
    const t = transactions.find(x=>x.txnId===txnId);
    if (t && t.status==='PENDING'){
      t.status='SUCCESS';
      t.completedAt = now();
    }
  }, ASYNC_TRANSFER_DELAY_MS);

  return res.status(202).json({
    status:202,
    message:'Transfer accepted',
    eta: limits.eta,
    willCompleteInSeconds: ASYNC_TRANSFER_DELAY_SECONDS,
    data: txn,
    updatedBalance: from.balance
  });
});
app.all('/transfer/fund', (req,res) => methodNotAllowed(res, ['POST']));

/**
 * @swagger
 * /transfer/status/{txnId}:
 *   get:
 *     summary: Get transfer status by txnId
 *     tags: [Transfers]
 *     security: [{ AccessTokenAuth: [] }]
 *     parameters:
 *       - in: path
 *         name: txnId
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200: { description: Status returned }
 *       400: { description: Bad request }
 *       401: { description: Unauthorized }
 *       404: { description: Transaction not found }
 */
app.get('/transfer/status/:txnId', accessTokenRequired, (req,res)=>{
  const id = Number(req.params.txnId);
  if (!Number.isInteger(id) || id<=0) return badRequest(res,'Route parameter "txnId" must be a positive integer');
  const txn = transactions.find(t=>t.txnId===id && t.customerId===req.customerId);
  if (!txn) return notFound(res,'Transaction not found');
  return res.status(200).json({ status:200, data: txn });
});
app.all('/transfer/status/:txnId', (req,res) => methodNotAllowed(res, ['GET']));

// ----------------------- Transactions -----------------------
/**
 * @swagger
 * /transactions:
 *   get:
 *     summary: Get transactions list
 *     description: Supports ETag caching. If-None-Match can return 304.
 *     tags: [Transactions]
 *     security: [{ AccessTokenAuth: [] }]
 *     parameters:
 *       - in: query
 *         name: accountId
 *         schema: { type: integer }
 *       - in: query
 *         name: status
 *         schema: { type: string, enum: [PENDING, SUCCESS, FAILED] }
 *       - in: query
 *         name: mode
 *         schema: { type: string, enum: [IMPS, NEFT, RTGS] }
 *     responses:
 *       200: { description: Transactions returned }
 *       304: { description: Not Modified (ETag matched) }
 *       400: { description: Bad request }
 *       401: { description: Unauthorized }
 */
app.get('/transactions', accessTokenRequired, (req,res)=>{
  if (!validateKnownParams(req.query, ['accountId','status','mode'], res)) return;
  const { accountId, status, mode } = req.query;

  let list = transactions.filter(t=>t.customerId===req.customerId);

  if (accountId !== undefined){
    const id = Number(accountId);
    if (!Number.isInteger(id) || id<=0) return badRequest(res,'Query param "accountId" must be a positive integer');
    list = list.filter(t=>t.fromAccountId===id);
  }
  if (status !== undefined){
    const v = String(status).trim().toUpperCase();
    if (!['PENDING','SUCCESS','FAILED'].includes(v)) return badRequest(res,'Query param "status" invalid');
    list = list.filter(t=>t.status===v);
  }
  if (mode !== undefined){
    const v = String(mode).trim().toUpperCase();
    if (!['IMPS','NEFT','RTGS'].includes(v)) return badRequest(res,'Query param "mode" invalid');
    list = list.filter(t=>t.mode===v);
  }

  return sendWithETag(req, res, { status:200, count:list.length, data:list });
});
app.all('/transactions', (req,res) => methodNotAllowed(res, ['GET']));

// ----------------------- Cards -----------------------
/**
 * @swagger
 * /cards:
 *   get:
 *     summary: Get cards
 *     tags: [Cards]
 *     security: [{ AccessTokenAuth: [] }]
 *     responses:
 *       200: { description: Cards returned }
 *       401: { description: Unauthorized }
 */
app.get('/cards', accessTokenRequired, (req,res)=>{
  const list = cards.filter(c=>c.customerId===req.customerId);
  return res.status(200).json({ status:200, count:list.length, data:list });
});
app.all('/cards', (req,res) => methodNotAllowed(res, ['GET']));

/**
 * @swagger
 * /cards/{cardId}/controls:
 *   patch:
 *     summary: Update card controls
 *     tags: [Cards]
 *     security: [{ AccessTokenAuth: [] }]
 *     parameters:
 *       - in: path
 *         name: cardId
 *         required: true
 *         schema: { type: integer }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               onlineEnabled: { type: boolean }
 *               atmEnabled: { type: boolean }
 *               domesticEnabled: { type: boolean }
 *               limitPerDay: { type: integer }
 *     responses:
 *       200: { description: Card updated }
 *       400: { description: Bad request }
 *       401: { description: Unauthorized }
 *       404: { description: Card not found }
 *       415: { description: Unsupported media type }
 */
app.patch('/cards/:cardId/controls', requireJson, accessTokenRequired, (req,res)=>{
  const id = Number(req.params.cardId);
  if (!Number.isInteger(id) || id<=0) return badRequest(res,'Route parameter "cardId" must be a positive integer');
  const card = cards.find(c=>c.cardId===id && c.customerId===req.customerId);
  if (!card) return notFound(res,'Card not found');

  const { onlineEnabled, atmEnabled, domesticEnabled, limitPerDay } = req.body || {};
  if (onlineEnabled !== undefined && typeof onlineEnabled !== 'boolean') return badRequest(res,'"onlineEnabled" must be boolean');
  if (atmEnabled !== undefined && typeof atmEnabled !== 'boolean') return badRequest(res,'"atmEnabled" must be boolean');
  if (domesticEnabled !== undefined && typeof domesticEnabled !== 'boolean') return badRequest(res,'"domesticEnabled" must be boolean');
  if (limitPerDay !== undefined){
    const n = Number(limitPerDay);
    if (!Number.isInteger(n) || n<=0) return badRequest(res,'"limitPerDay" must be a positive integer');
    card.limitPerDay = n;
  }
  if (onlineEnabled !== undefined) card.onlineEnabled = onlineEnabled;
  if (atmEnabled !== undefined) card.atmEnabled = atmEnabled;
  if (domesticEnabled !== undefined) card.domesticEnabled = domesticEnabled;

  return res.status(200).json({ status:200, message:'Card controls updated', data:card });
});
app.all('/cards/:cardId/controls', (req,res) => methodNotAllowed(res, ['PATCH']));

// ----------------------- Loans -----------------------
/**
 * @swagger
 * /loans:
 *   get:
 *     summary: Get loans
 *     tags: [Loans]
 *     security: [{ AccessTokenAuth: [] }]
 *     responses:
 *       200: { description: Loans returned }
 *       401: { description: Unauthorized }
 */
app.get('/loans', accessTokenRequired, (req,res)=>{
  const list = loans.filter(l=>l.customerId===req.customerId);
  return res.status(200).json({ status:200, count:list.length, data:list });
});
app.all('/loans', (req,res) => methodNotAllowed(res, ['GET']));

// ----------------------- Admin APIs (Role-based 403) -----------------------

/**
 * @swagger
 * /admin/transactions/all:
 *   get:
 *     summary: ADMIN ONLY - Get all transactions of all customers
 *     tags: [Admin]
 *     security: [{ AccessTokenAuth: [] }]
 *     responses:
 *       200: { description: All transactions returned }
 *       401: { description: Unauthorized }
 *       403: { description: Forbidden (requires ADMIN role) }
 */
app.get('/admin/transactions/all', accessTokenRequired, requireRole(['ADMIN']), (req,res)=>{
  return res.status(200).json({ status:200, count:transactions.length, data:transactions });
});
app.all('/admin/transactions/all', (req,res) => methodNotAllowed(res, ['GET']));

/**
 * @swagger
 * /admin/customers:
 *   get:
 *     summary: ADMIN ONLY - Get customer list (demo)
 *     tags: [Admin]
 *     security: [{ AccessTokenAuth: [] }]
 *     responses:
 *       200: { description: Customers returned }
 *       401: { description: Unauthorized }
 *       403: { description: Forbidden }
 */
app.get('/admin/customers', accessTokenRequired, requireRole(['ADMIN']), (req,res)=>{
  const list = customers.map(c => ({
    customerId: c.customerId,
    username: c.username,
    fullName: c.fullName,
    mobile: c.mobile,
    role: c.role
  }));
  return res.status(200).json({ status:200, count:list.length, data:list });
});
app.all('/admin/customers', (req,res) => methodNotAllowed(res, ['GET']));

// ----------------------- Demo endpoints -----------------------
/**
 * @swagger
 * /limited:
 *   get:
 *     summary: Rate limited endpoint (429 demo)
 *     tags: [Demos]
 *     responses:
 *       200: { description: OK }
 *       429: { description: Too Many Requests }
 */
app.get('/limited', (req,res,next)=>{
  const ip = (req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
  const WINDOW_MS = 60*1000; const MAX_REQ = 5;
  const store = (app.rateStore ||= new Map());
  const t = Date.now();
  const rec = store.get(ip) || { count:0, timestamp:t };
  if (t - rec.timestamp > WINDOW_MS){ rec.count=0; rec.timestamp=t; }
  rec.count++; store.set(ip, rec);
  if (rec.count > MAX_REQ){ const retryAfter = Math.ceil((rec.timestamp+WINDOW_MS - t)/1000); return tooManyRequests(res, retryAfter); }
  next();
}, (req,res)=>res.status(200).json({ status:200, message:'OK' }));
app.all('/limited', (req,res) => methodNotAllowed(res, ['GET']));

/**
 * @swagger
 * /simulate-error:
 *   get:
 *     summary: Simulate 500 error
 *     tags: [Demos]
 *     responses:
 *       500: { description: Internal Server Error }
 */
app.get('/simulate-error', (req,res)=>res.status(500).json({ status:500, error:'Internal Server Error', message:'Simulated failure' }));
app.all('/simulate-error', (req,res) => methodNotAllowed(res, ['GET']));

/**
 * @swagger
 * /:
 *   get:
 *     summary: Root endpoint
 *     tags: [Meta]
 *     responses:
 *       200: { description: API info }
 */
app.get('/', (req,res)=>{
  res.status(200).json({
    status:'ok',
    message:'Advanced Mock Banking API running',
    supports: {
      etagCaching: ['GET /accounts', 'GET /transactions'],
      roleBased: ['GET /admin/* requires ADMIN'],
      methodNotAllowed: '405 + Allow header',
      deleteNoContent: ['DELETE /beneficiaries/:id returns 204']
    },
    flow:{
      step1:'POST /auth/login -> otpSessionId + demoOtp',
      step2:'POST /auth/verify-otp -> accessToken + refreshToken',
      refresh:'POST /auth/refresh-token'
    },
    endpoints:[
      'POST /auth/login',
      'POST /auth/verify-otp',
      'POST /auth/refresh-token',
      'POST /auth/logout',
      'GET /customer/profile',
      'GET /accounts (ETag/304)',
      'GET /accounts/:accountId/balance',
      'POST /accounts/:accountId/freeze',
      'GET/POST /beneficiaries',
      'DELETE /beneficiaries/:beneficiaryId (204)',
      'POST /transfer/fund (async)',
      'GET /transfer/status/:txnId',
      'GET /transactions (ETag/304)',
      'GET /cards',
      'PATCH /cards/:cardId/controls',
      'GET /loans',
      'GET /admin/transactions/all (ADMIN)',
      'GET /admin/customers (ADMIN)',
      'GET /limited',
      'GET /simulate-error',
      'GET /api-docs'
    ],
    notes:{
      strictParams: STRICT_PARAMS,
      ttlMinutes: TTL_MINUTES,
      accessTokenTtlMinutes: ACCESS_TOKEN_TTL_MINUTES,
      refreshTokenTtlDays: REFRESH_TOKEN_TTL_DAYS
    }
  });
});
app.all('/', (req,res) => methodNotAllowed(res, ['GET']));

// Global error handler
app.use((err, req, res, next)=>{
  console.error('Unhandled error:', err);
  return res.status(500).json({ status:500, error:'Internal Server Error', message: err?.message || 'Unexpected error' });
});

app.listen(PORT, '0.0.0.0', ()=> console.log(`Advanced Mock Banking API running at http://localhost:${PORT}`));
