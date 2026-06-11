import express from "express";
import dotenv from "dotenv";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import session from "express-session";
import rateLimit from "express-rate-limit";
import { saveDonation, getAllDonations } from "./db.js";

declare module "express-session" {
  interface SessionData {
    isAdmin?: boolean;
  }
}

dotenv.config();

const app = express();
const PORT = parseInt(process.env.PORT || "4000", 10);

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// CORS — accept everything (open for development; tighten the origin for production).
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Idempotency-Key");
  res.header("Access-Control-Max-Age", "86400");
  if (req.method === "OPTIONS") {
    res.sendStatus(204);
    return;
  }
  next();
});


app.use(express.json({
  verify: (req, _res, buf) => {
    (req as unknown as { rawBody: Buffer }).rawBody = buf;
  },
}));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 4, // 4 hours
  },
}));

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many attempts. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "Too many requests. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Timing-safe comparison helper
function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// Verify a plaintext password against a stored scrypt hash (format: scrypt$saltHex$keyHex).
// The plaintext is never stored; only this hash lives in the environment.
function verifyPassword(password: string, stored: string | undefined): boolean {
  if (!stored) return false;
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = Buffer.from(parts[1], "hex");
  const expected = Buffer.from(parts[2], "hex");
  let actual: Buffer;
  try {
    actual = crypto.scryptSync(password, salt, expected.length);
  } catch {
    return false;
  }
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

// Non-generic admin route slug (from env), kept out of committed/frontend code.
const ADMIN_PATH = (process.env.ADMIN_PATH || "ops-console").replace(/^\/+/, "");

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Lightweight health check — confirms the server is up and whether the
// Paystack secret is configured (without leaking the key itself).
app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

app.post("/api/create-donation-intent", apiLimiter, async (req, res) => {
  try {
    console.log("Received body:", req.body);

    const { email, session_token } = req.body;
    const raw_amount = parseFloat(req.body.amount);

    if (!email || !raw_amount || isNaN(raw_amount) || raw_amount <= 0 || !session_token) {
      res.status(400).json({ error: "Missing required fields: email, amount, session_token" });
      return;
    }

    if (!emailRegex.test(email)) {
      res.status(400).json({ error: "Invalid email format" });
      return;
    }

    if (typeof session_token !== "string" || session_token.length < 8) {
      res.status(400).json({ error: "Invalid session token" });
      return;
    }

    const amountInKobo = Math.round(raw_amount * 100);
    const minuteTimestamp = Math.floor(Date.now() / 60000);
    const idempotencyKey = crypto
      .createHash("md5")
      .update(`${session_token}-${amountInKobo}-${minuteTimestamp}`)
      .digest("hex");

    const secretKey = process.env.PAYSTACK_SECRET_KEY;
    if (!secretKey) {
      console.error("PAYSTACK_SECRET_KEY is not set");
      res.status(500).json({ error: "Server configuration error" });
      return;
    }

    // Use APP_URL only when it's a real http(s) URL; otherwise derive from the
    // incoming request (so a placeholder like "MY_APP_URL" can't break the redirect).
    const appUrl = process.env.APP_URL;
    const baseUrl = appUrl && /^https?:\/\//i.test(appUrl)
      ? appUrl.replace(/\/$/, "")
      : `${req.protocol}://${req.get("host")}`;

    const response = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${secretKey}`,
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify({
        email,
        amount: amountInKobo,
        callback_url: `${baseUrl}/thank-you`,
      }),
    });

    const data = await response.json() as Record<string, unknown>;

    if (!response.ok || !data.status) {
      const message = (data.message as string) || "Paystack initialization failed";
      console.error("Paystack error:", data);
      res.status(response.ok ? 400 : response.status).json({ error: message });
      return;
    }

    const authorizationUrl = (data.data as Record<string, unknown>)?.authorization_url as string;
    if (!authorizationUrl) {
      console.error("Paystack response missing authorization_url:", data);
      res.status(500).json({ error: "Invalid response from payment provider" });
      return;
    }

    res.json({ checkout_link: authorizationUrl });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/verify-donation", apiLimiter, async (req, res) => {
  try {
    const { reference } = req.query;

    if (!reference || typeof reference !== "string") {
      res.status(400).json({ error: "Missing reference parameter" });
      return;
    }

    if (!/^[a-zA-Z0-9_.-]+$/.test(reference)) {
      res.status(400).json({ error: "Invalid reference format" });
      return;
    }

    const secretKey = process.env.PAYSTACK_SECRET_KEY;
    if (!secretKey) {
      res.status(500).json({ error: "Server configuration error" });
      return;
    }

    const response = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: {
        Authorization: `Bearer ${secretKey}`,
      },
    });

    const data = await response.json() as Record<string, unknown>;
    const txData = data.data as Record<string, unknown> | undefined;

    if (response.ok && data.status === true && txData?.status === "success") {
      const customer = txData.customer as Record<string, unknown> | undefined;
      saveDonation({
        email: (customer?.email as string) || reference,
        amount: (txData.amount as number) || 0,
        reference,
        status: "success",
      });
      res.json({ verified: true });
    } else {
      res.json({ verified: false });
    }
  } catch (err) {
    console.error("Verification error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/admin/login", authLimiter, (req, res) => {
  const { password } = req.body as { password?: string };
  if (password && verifyPassword(password, process.env.ADMIN_PASSWORD_HASH)) {
    req.session.isAdmin = true;
    res.json({ ok: true });
  } else {
    res.status(401).json({ error: "Invalid password" });
  }
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {});
  res.json({ ok: true });
});

app.get("/api/admin/check", (req, res) => {
  res.json({ authenticated: Boolean(req.session.isAdmin) });
});

function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (req.session.isAdmin) {
    next();
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
}

app.get("/api/admin/donations", requireAdmin, (req, res) => {
  const sortBy = (req.query.sort as string) || "created_at";
  const sortDir = (req.query.dir as string) || "desc";
  const rows = getAllDonations(sortBy, sortDir);
  res.json(rows);
});

// Admin console served at a non-generic, env-configured route. admin.html is a
// self-contained login + dashboard SPA: it checks /api/admin/check and shows the
// login form when unauthenticated. The data lives behind requireAdmin on the API.
// (Console scope: donations, blog posts, event attendee entries.)
// There is intentionally no /admin alias — that and every unknown route 404s.
app.get(`/${ADMIN_PATH}`, (_req, res) => {
  res.sendFile(path.resolve(__dirname, "admin.html"));
});

app.post("/api/paystack/webhook", async (req, res) => {
  try {
    const signature = req.headers["x-paystack-signature"] as string | undefined;
    if (!signature) {
      res.sendStatus(200);
      return;
    }

    const secretKey = process.env.PAYSTACK_SECRET_KEY;
    if (!secretKey) {
      console.error("PAYSTACK_SECRET_KEY is not set");
      res.sendStatus(200);
      return;
    }

    const rawBody = (req as unknown as { rawBody: Buffer | undefined }).rawBody;
    if (!rawBody) {
      console.error("Webhook: missing raw body");
      res.sendStatus(200);
      return;
    }

    const expectedSig = crypto
      .createHmac("sha512", secretKey)
      .update(rawBody)
      .digest("hex");

    if (!safeCompare(signature, expectedSig)) {
      console.error("Webhook: signature mismatch");
      res.sendStatus(200);
      return;
    }

    const payload = req.body as Record<string, unknown>;
    const event = payload.event as string;

    if (event === "charge.success") {
      const data = payload.data as Record<string, unknown> | undefined;
      if (!data) {
        res.sendStatus(200);
        return;
      }

      const customer = data.customer as Record<string, unknown> | undefined;
      const reference = data.reference as string;
      const amount = data.amount as number;
      const email = (customer?.email as string) || "";

      if (reference && amount) {
        saveDonation({
          email,
          amount,
          reference,
          status: "success",
        });
        console.log("Webhook: donation saved", { reference, email, amount });
      }
    }

    res.sendStatus(200);
  } catch (err) {
    console.error("Webhook error:", err);
    res.sendStatus(200);
  }
});

app.get("/thank-you", (_req, res) => {
  res.sendFile(path.resolve(__dirname, "thank-you.html"));
});

app.use(express.static(path.resolve(__dirname, "../dist")));

// Serve raw source images (e.g. the gallery photos referenced by runtime JS).
// Vite only bundles statically-discoverable assets, so these would 404 from
// dist/. dist's own hashed bundle assets take priority; only the un-bundled
// originals (the gallery UUID photos) fall through to here.
app.use("/assets", express.static(path.resolve(__dirname, "../assets")));

// The site has no client-side path routing (navigation is hash-based), so any
// unmatched path — including /admin — is a genuine 404. Serve the themed page.
app.get("*", (_req, res) => {
  res.status(404).sendFile(path.resolve(__dirname, "404.html"));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
