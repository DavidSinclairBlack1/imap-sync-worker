require("dotenv").config();

const express = require("express");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const { ImapFlow } = require("imapflow");
const { simpleParser } = require("mailparser");

const PORT = process.env.PORT || 3001;
const SYNC_INTERVAL_SECONDS = Number(process.env.SYNC_INTERVAL_SECONDS || 300);
const WORKER_API_KEY = (process.env.WORKER_API_KEY || "").trim();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

if (!WORKER_API_KEY) {
  console.error("❌ Missing WORKER_API_KEY");
}

const subtle = crypto.webcrypto.subtle;

function b64ToU8(b64) {
  const clean = b64.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(clean, "base64"));
}

async function decryptCredential(encryptedValueB64, ivB64) {
  try {
    const keyBytes = b64ToU8(process.env.CREDENTIAL_ENCRYPTION_KEY);
    if (keyBytes.length !== 32) {
      throw new Error(`Key must be 32 bytes, got ${keyBytes.length}`);
    }
    const iv = b64ToU8(ivB64);
    const data = b64ToU8(encryptedValueB64);
    const cryptoKey = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
    const plaintext = await subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, data);
    return Buffer.from(plaintext).toString("utf8");
  } catch (e) {
    throw new Error(`Decrypt failed: ${e.message}`);
  }
}

async function getImapPassword(emailAccountId) {
  const { data, error } = await supabase
    .from("AccountCredentials")
    .select("encrypted_value, encryption_iv")
    .eq("email_account_id", emailAccountId)
    .eq("credential_type", "imap_password")
    .single();
  if (error) throw error;
  if (!data) throw new Error("No IMAP password found");
  return await decryptCredential(data.encrypted_value, data.encryption_iv);
}

function addrToEmail(addr) {
  if (!addr) return "";
  if (typeof addr === "string") return addr;
  return addr.address || "";
}

function firstAddr(list) {
  if (!Array.isArray(list) || list.length === 0) return "";
  return addrToEmail(list[0]);
}

async function syncInboxOnce(account) {
  const password = await getImapPassword(account.id);
  const client = new ImapFlow({
    host: account.imap_host,
    port: Number(account.imap_port || 993),
    secure: Number(account.imap_port || 993) === 993,
    auth: { user: account.imap_user || account.email, pass: password },
    logger: false,
    socketTimeout: 30000,
    greetingTimeout: 10000,
    connectionTimeout: 10000,
  });

  client.on('error', (err) => {
    console.error(`[IMAP error] ${account.email}:`, err.message);
  });

  await client.connect();
  try {
    await client.mailboxOpen("INBOX", { readOnly: true });
    const uidNext = client.mailbox.uidNext || 1;
    const uidValidity = client.mailbox.uidValidity || null;
    const highUid = Math.max(uidNext - 1, 0);
    const lastUid = account.folder_sync_state?.INBOX?.last_uid != null ? Number(account.folder_sync_state.INBOX.last_uid) : 0;
    if (highUid <= lastUid) {
      return { inserted: 0, highUid, lastUid };
    }
    const startUid = Math.max(lastUid + 1, Math.max(highUid - 50, 1));
    const range = `${startUid}:${highUid}`;
    const rows = [];
    for await (const msg of client.fetch(range, {
      uid: true,
      envelope: true,
      flags: true,
      internalDate: true,
      source: { start: 0, maxLength: 32768 },
    })) {
      const env = msg.envelope || {};
      const fromEmail = firstAddr(env.from);
      const toEmail = firstAddr(env.to);
      const rawSource = msg.source?.toString("utf8") || "";
      let body_html = "";
      let body_text = "";
      if (rawSource) {
        try {
          const parsed = await simpleParser(rawSource);
          body_html = parsed.html || "";
          body_text = parsed.text || "";
        } catch (e) {
          console.error(`Parse error for UID ${msg.uid}:`, e.message);
        }
      }
      const messageId = (env.messageId || "").replace(/[<>]/g, "");
      const isOutbound = fromEmail.toLowerCase() === account.email.toLowerCase();
      rows.push({
        user_id: account.user_id,
        email_account_id: account.id,
        message_id: messageId,
        from_email: fromEmail,
        to_email: toEmail,
        subject: env.subject || "",
        received_at: msg.internalDate || new Date(),
        direction: isOutbound ? "sent" : "received",
        is_unread: !(msg.flags || []).includes("\\Seen"),
        body_html: body_html,
        body_text: body_text,
      });
    }
    if (rows.length) {
      const { error: upsertErr } = await supabase.from("Emails").upsert(rows, { onConflict: "user_id,message_id" });
      if (upsertErr) throw upsertErr;
    }
    const newState = {
      ...(account.folder_sync_state || {}),
      INBOX: {
        last_uid: highUid,
        uidvalidity: uidValidity,
        synced_at: new Date().toISOString(),
      },
    };
    const { error: stateErr } = await supabase.from("EmailAccounts").update({ folder_sync_state: newState }).eq("id", account.id);
    if (stateErr) throw stateErr;
    return { inserted: rows.length, highUid, lastUid };
  } finally {
    try { await client.logout(); } catch {}
    try { client.close(); } catch {}
  }
}

async function syncAllAccountsOnce() {
  const { data: accounts, error } = await supabase
    .from("EmailAccounts")
    .select("id,email,user_id,imap_host,imap_port,imap_user,folder_sync_state")
    .eq("status", "active");
  if (error) throw error;
  if (!accounts || !accounts.length) return;
  for (const acct of accounts) {
    try {
      const res = await syncInboxOnce(acct);
      console.log(`[sync] ${acct.email} inserted=${res.inserted} last=${res.lastUid} high=${res.highUid}`);
    } catch (e) {
      console.error(`[sync] ${acct.email} failed:`, e.message || e);
    }
  }
}

function startLoop() {
  console.log("🚀 IMAP sync worker starting...");
  syncAllAccountsOnce().catch((e) => console.error("Initial sync failed:", e));
  setInterval(() => {
    syncAllAccountsOnce().catch((e) => console.error("Sync loop failed:", e));
  }, SYNC_INTERVAL_SECONDS * 1000);
}

const app = express();
app.use(express.json());

function requireWorkerKey(req, res, next) {
  if (req.path === "/health") return next();
  const key = (req.get("x-api-key") || "").trim();
  if (!WORKER_API_KEY) {
    return res.status(500).json({ ok: false, error: "WORKER_API_KEY not set" });
  }
  if (key !== WORKER_API_KEY) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

app.use(requireWorkerKey);
app.get("/health", (_req, res) => res.json({ ok: true }));
app.post("/sync", async (_req, res) => {
  try {
    await syncAllAccountsOnce();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
});

app.post("/credentials/imap-password", async (req, res) => {
  try {
    const { email_account_id, password } = req.body;
    if (!email_account_id || !password) {
      return res.status(400).json({ ok: false, error: "Missing email_account_id or password" });
    }
    const keyBytes = b64ToU8(process.env.CREDENTIAL_ENCRYPTION_KEY);
    if (keyBytes.length !== 32) {
      return res.status(500).json({ ok: false, error: "Invalid encryption key length" });
    }
    const iv = crypto.randomBytes(12);
    const cryptoKey = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
    const encrypted = await subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, Buffer.from(password, "utf8"));
    const encrypted_value = Buffer.from(encrypted).toString("base64");
    const encryption_iv = Buffer.from(iv).toString("base64");
    const { error } = await supabase.from("AccountCredentials").upsert(
      { email_account_id, credential_type: "imap_password", encrypted_value, encryption_iv },
      { onConflict: "email_account_id,credential_type" }
    );
    if (error) throw error;
    res.json({ ok: true, message: "Password encrypted and stored" });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.listen(PORT, () => {
  startLoop();
  console.log(`✅ Listening on port ${PORT}`);
});
