require("dotenv").config();
BigInt.prototype.toJSON = function() { return Number(this); };
const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
const { ImapFlow } = require("imapflow");
const { simpleParser } = require("mailparser");
const { parse } = require('csv-parse/sync');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3001;
const SYNC_INTERVAL = (parseInt(process.env.SYNC_INTERVAL_SECONDS) || 300) * 1000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const { subtle } = crypto.webcrypto;

function b64ToU8(b64) { return new Uint8Array(Buffer.from(b64, "base64")); }

async function decryptPassword(encVal, ivB64) {
  // Use EMAIL_ENCRYPTION_KEY (same as Supabase), padded to 32 chars
  const key = process.env.EMAIL_ENCRYPTION_KEY || process.env.CREDENTIAL_ENCRYPTION_KEY;
  if (!key) throw new Error("No encryption key found");
  const paddedKey = key.padEnd(32, '0').slice(0, 32);
  const keyBytes = new TextEncoder().encode(paddedKey);
  const cryptoKey = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const decrypted = await subtle.decrypt({ name: "AES-GCM", iv: b64ToU8(ivB64) }, cryptoKey, b64ToU8(encVal));
  return new TextDecoder().decode(decrypted);
}

async function getAccountCredentials(accountId, credType) {
  const { data: creds } = await supabase.from("AccountCredentials").select("encrypted_value, encryption_iv").eq("email_account_id", accountId).eq("credential_type", credType).single();
  if (!creds) return null;
  return await decryptPassword(creds.encrypted_value, creds.encryption_iv);
}

async function syncAccount(account) {
  const password = await getAccountCredentials(account.id, "imap_password");
  if (!password) throw new Error("No password");
  const client = new ImapFlow({ host: account.imap_host, port: account.imap_port || 993, secure: true, auth: { user: account.email, pass: password }, tls: { rejectUnauthorized: false }, logger: false });
  client.on("error", (err) => console.log(`[IMAP error] ${account.email}:`, err.message));
  await client.connect();
  const lock = await client.getMailboxLock("INBOX");
  try {
    const status = await client.status("INBOX", { uidValidity: true, uidNext: true });
    const uidValidity = status.uidValidity;
    const prevState = account.folder_sync_state?.INBOX || {};
    let searchCriteria = { seen: false };
    if (prevState.uidvalidity === uidValidity && prevState.last_uid) searchCriteria = { uid: `${prevState.last_uid + 1}:*` };
    const messages = [];
    for await (let msg of client.fetch(searchCriteria, { uid: true, flags: true, bodyStructure: true, envelope: true, source: true, internalDate: true })) messages.push(msg);
    if (messages.length === 0) { console.log(`[sync] ${account.email}: No new messages`); return; }
    console.log(`[sync] ${account.email}: Found ${messages.length} new emails`);
    let highUid = prevState.last_uid || 0;
    const rows = [];
    for (const msg of messages) {
      if (Number(msg.uid) > highUid) highUid = Number(msg.uid);
      const parsed = await simpleParser(msg.source);
      const env = msg.envelope || {};
      const fromEmail = env.from?.[0]?.address || "";
      const toEmail = env.to?.[0]?.address || "";
      let body_html = parsed.html || "";
      let body_text = parsed.text || "";
      if (!body_html && body_text) body_html = `<pre>${body_text}</pre>`;
      if (!body_text && body_html) body_text = body_html.replace(/<[^>]+>/g, "");
      const messageId = (env.messageId || "").replace(/[<>]/g, "");
      const isOutbound = fromEmail.toLowerCase() === account.email.toLowerCase();
      rows.push({ user_id: account.user_id, email_account_id: account.id, message_id: messageId, from_address_email: fromEmail, to_address_email_list: [toEmail], subject: env.subject || "", timestamp_email: new Date(msg.internalDate || Date.now()), direction: isOutbound ? "sent" : "received", is_unread: !Array.isArray(msg.flags) || !msg.flags.includes("\\Seen"), body_html, body_text, imap_folder: "INBOX", imap_uid: Number(msg.uid), imap_uidvalidity: Number(uidValidity) });
    }
    if (rows.length) { const { error: upsertErr } = await supabase.from("Emails").upsert(rows, { onConflict: "user_id,message_id" }); if (upsertErr) throw upsertErr; }
    const newState = { ...(account.folder_sync_state || {}), INBOX: { last_uid: Number(highUid), uidvalidity: uidValidity, synced_at: new Date().toISOString() } };
    await supabase.from("EmailAccounts").update({ folder_sync_state: newState }).eq("id", account.id);
    console.log(`[sync] ${account.email}: Synced ${rows.length} emails successfully`);
  } finally { lock.release(); await client.logout(); }
}

async function syncAllAccounts() {
  const { data: accounts } = await supabase.from("EmailAccounts").select("*");
  if (!accounts || accounts.length === 0) return;
  for (const acc of accounts) { try { await syncAccount(acc); } catch (err) { console.log(`[sync] ${acc.email} failed:`, err.message); } }
}

let loopTimer = null;
function startLoop() { if (loopTimer) clearInterval(loopTimer); syncAllAccounts(); loopTimer = setInterval(syncAllAccounts, SYNC_INTERVAL); }

app.get("/health", (req, res) => res.json({ ok: true }));

const apiKeyMiddleware = (req, res, next) => { if (req.headers["x-api-key"] !== process.env.WORKER_API_KEY) return res.status(401).json({ ok: false, error: "Unauthorized" }); next(); };

const jwtAuthMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ ok: false, error: "Missing authorization header" });
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.sub) return res.status(401).json({ ok: false, error: "Invalid token" });
    req.user_id = decoded.sub;
    next();
  } catch (error) { return res.status(401).json({ ok: false, error: "Invalid or expired token" }); }
};

app.post("/sync", apiKeyMiddleware, async (req, res) => { try { await syncAllAccounts(); res.json({ ok: true, message: "Sync triggered" }); } catch (e) { res.status(500).json({ ok: false, error: e.message }); } });

// Optional auth - allows requests without strict user checking
const optionalAuthMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.substring(7);
      const decoded = jwt.decode(token);
      if (decoded && decoded.sub) req.user_id = decoded.sub;
    } catch (error) {}
  }
  next();
};

// Get all accounts endpoint (no user filter)
app.get("/accounts", optionalAuthMiddleware, async (req, res) => {
  try {
    const { data: accounts, error } = await supabase
      .from('EmailAccounts')
      .select('*')
      .order('email', { ascending: true });
    if (error) throw error;
    res.json({ ok: true, accounts: accounts || [], total: accounts?.length || 0 });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/upload-csv", jwtAuthMiddleware, async (req, res) => {
  try {
    const { csv_content, workspace_id } = req.body;
    const user_id = req.user_id;
    if (!csv_content) return res.status(400).json({ ok: false, error: "Missing csv_content" });
    let ws_id = workspace_id;
    if (!ws_id) {
      const { data: ownedWorkspace } = await supabase.from('Workspaces').select('id').eq('owner_user_id', user_id).limit(1).single();
      if (ownedWorkspace?.id) ws_id = ownedWorkspace.id;
      else {
        const { data: newWorkspace, error: wsError } = await supabase.from('Workspaces').insert({ owner_user_id: user_id, name: 'Default Workspace' }).select().single();
        if (wsError) return res.status(500).json({ ok: false, error: "Failed to create workspace" });
        ws_id = newWorkspace.id;
      }
    }
    const records = parse(csv_content, { columns: true, skip_empty_lines: true, trim: true });
    const results = { success: [], failed: [] };
    for (const row of records) {
      try {
        const email = row['Email'], imapPassword = row['IMAP Password'], imapHost = row['IMAP Host'], imapPort = parseInt(row['IMAP Port']) || 993;
        const smtpPassword = row['SMTP Password'] || imapPassword, smtpHost = row['SMTP Host'] || imapHost, smtpPort = parseInt(row['SMTP Port']) || 587;
        if (!email || !imapPassword) { results.failed.push({ email, error: 'Missing email or password' }); continue; }
        const { data: account, error: accountError } = await supabase.from('EmailAccounts').upsert({ user_id, workspace_id: ws_id, email, imap_host: imapHost, imap_port: imapPort, smtp_host: smtpHost, smtp_port: smtpPort }, { onConflict: 'user_id,email' }).select().single();
        if (accountError) throw accountError;
        const keyBytes = b64ToU8(process.env.CREDENTIAL_ENCRYPTION_KEY);
        const ivImap = crypto.randomBytes(12);
        const cryptoKeyImap = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
        const encryptedImap = await subtle.encrypt({ name: "AES-GCM", iv: ivImap }, cryptoKeyImap, Buffer.from(imapPassword, "utf8"));
        await supabase.from("AccountCredentials").upsert({ email_account_id: account.id, credential_type: "imap_password", encrypted_value: Buffer.from(encryptedImap).toString("base64"), encryption_iv: Buffer.from(ivImap).toString("base64") }, { onConflict: "email_account_id,credential_type" });
        const ivSmtp = crypto.randomBytes(12);
        const cryptoKeySmtp = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
        const encryptedSmtp = await subtle.encrypt({ name: "AES-GCM", iv: ivSmtp }, cryptoKeySmtp, Buffer.from(smtpPassword, "utf8"));
        await supabase.from("AccountCredentials").upsert({ email_account_id: account.id, credential_type: "smtp_password", encrypted_value: Buffer.from(encryptedSmtp).toString("base64"), encryption_iv: Buffer.from(ivSmtp).toString("base64") }, { onConflict: "email_account_id,credential_type" });
        results.success.push({ email, account_id: account.id });
      } catch (err) { results.failed.push({ email: row['Email'], error: err.message }); }
    }
    res.json({ ok: true, message: `Processed ${records.length} accounts`, results });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Send email via SMTP
// CORS preflight handler
app.options("/send", (req, res) => {
  res.set({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  }).status(200).end();
});

app.post("/send", jwtAuthMiddleware, async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  try {
    const { email_account_id, to, subject, body_html, body_text } = req.body;
    
    if (!email_account_id || !to || (!body_html && !body_text)) {
      return res.status(400).json({ ok: false, error: "Missing required fields" });
    }
    
    const { data: account } = await supabase.from('EmailAccounts').select('*').eq('id', email_account_id).single();
    if (!account) return res.status(404).json({ ok: false, error: "Email account not found" });
    
    let password = await getAccountCredentials(email_account_id, "smtp_password");
    if (!password) password = await getAccountCredentials(email_account_id, "imap_password");
    if (!password) return res.status(400).json({ ok: false, error: "No credentials found" });
    
    console.log(`[send] Sending from ${account.email} to ${to} via SMTP proxy`);
    
    // Use Contabo SMTP proxy
    const proxyResponse = await fetch('http://167.86.124.72:3000/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: account.email,
        to: Array.isArray(to) ? to.join(',') : to,
        subject: subject || '',
        html: body_html || '',
        text: body_text || '',
        password: password
      })
    });
    
    const result = await proxyResponse.json();
    
    if (!result.ok) throw new Error(result.error);
    
    const messageId = result.messageId || `sent-${Date.now()}`;
    
    // Store in database
    await supabase.from('Emails').insert({
      user_id: account.user_id,
      email_account_id,
      message_id: messageId,
      from_address_email: account.email,
      to_address_email_list: Array.isArray(to) ? to : [to],
      subject: subject || '',
      timestamp_email: new Date(),
      direction: 'sent',
      is_unread: false,
      body_html: body_html || '',
      body_text: body_text || '',
      imap_folder: 'SENT',
    });
    
    res.json({ ok: true, message_id: messageId });
  } catch (e) {
    console.log('[send] Error:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
})

app.listen(PORT, () => { startLoop(); console.log(`✅ Listening on port ${PORT}`); });
