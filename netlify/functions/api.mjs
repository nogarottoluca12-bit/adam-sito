/* =========================================================
   ADAM'S — memoria del sito su Netlify (Netlify Function + Netlify Blobs)
   Salva: prenotazioni, messaggi, richieste di catering, ordini dello shop,
   iscrizioni alla newsletter, contenuti dell'Area riservata e foto caricate.
   Password dell'Area riservata: variabile d'ambiente ADMIN_PASSWORD
   (Netlify › Project configuration › Environment variables). Se manca: "mary".
   ========================================================= */
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api" };

const PUBLIC_DOCS = ["settings", "menu", "shop", "events", "art"];
const MOMENTS = ["Breakfast", "Brunch", "Lunch", "Aperitivo", "Dinner"];
const KINDS = ["late", "cancel", "more", "fewer", "other", "newsletter", "catering", "order"];
const MAX_DOC = 1500000;
const MAX_IMG = 5500000;
const COOKIE = "adams_admin";

const env = (k) => { try { const v = globalThis.Netlify?.env?.get?.(k); if (v) return v; } catch (e) {} return process.env[k]; };
const password = () => (env("ADMIN_PASSWORD") || "mary").trim();
const secret = () => env("ADAMS_SECRET") || crypto.createHash("sha256").update("adams|" + password() + "|" + (env("SITE_ID") || "site")).digest("hex");
const db = () => getStore({ name: "adams", consistency: "strong" });
const pics = () => getStore({ name: "adams-img", consistency: "strong" });

/* ---------- utilità ---------- */
const json = (obj, status = 200, headers = {}) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers } });
const fail = (msg, status = 400) => json({ ok: false, error: msg }, status);
const s = (v, n = 300) => { if (typeof v !== "string" && typeof v !== "number") return ""; return String(v).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim().slice(0, n); };
const isDate = (v) => typeof v === "string" && /^\d{4}-\d\d-\d\d$/.test(v);
const isEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v || "");
const newId = (p) => p + Date.now().toString(36) + crypto.randomBytes(3).toString("hex");
const today = () => new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Zurich", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
const hmac = (x) => crypto.createHmac("sha256", secret()).update(x).digest("base64url");
const safeEq = (a, b) => { const A = Buffer.from(String(a)), B = Buffer.from(String(b)); return A.length === B.length && crypto.timingSafeEqual(A, B); };

/* ---------- sessione della proprietaria (cookie firmato) ---------- */
function makeToken() { const p = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600e3, n: crypto.randomBytes(8).toString("hex") })).toString("base64url"); return p + "." + hmac(p); }
function readToken(req) {
  const c = req.headers.get("cookie") || ""; const m = c.match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)")); if (!m) return null;
  const [p, sig] = m[1].split("."); if (!p || !sig || !safeEq(hmac(p), sig)) return null;
  try { const d = JSON.parse(Buffer.from(p, "base64url").toString()); if (!d.exp || d.exp < Date.now()) return null; } catch (e) { return null; }
  return m[1];
}
const csrfOf = (tok) => hmac(tok + "|csrf");
const cookieHeader = (val, maxAge, req) => { const https = new URL(req.url).protocol === "https:"; return `${COOKIE}=${val}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${https ? "; Secure" : ""}`; };

/* ---------- archivio ---------- */
async function readDoc(key, def = null) { try { const v = await db().get(key, { type: "json" }); return v ?? def; } catch (e) { return def; } }
/* lettura-modifica-scrittura sicura anche con due richieste contemporanee */
async function update(key, fn) {
  for (let i = 0; i < 8; i++) {
    const cur = await db().getWithMetadata(key, { type: "json" });
    const r = await fn(cur ? cur.data : null);
    if (!r || !("value" in r)) return r ? r.ret : undefined;
    const res = cur ? await db().setJSON(key, r.value, { onlyIfMatch: cur.etag }) : await db().setJSON(key, r.value, { onlyIfNew: true });
    if (!res || res.modified !== false) return r.ret;
    await new Promise((ok) => setTimeout(ok, 60 + Math.random() * 120));
  }
  throw new Error("busy");
}
const bookingsDoc = (d) => { d = d && typeof d === "object" ? d : {}; return { items: Array.isArray(d.items) ? d.items : [], msgs: Array.isArray(d.msgs) ? d.msgs : [] }; };
const slotsFrom = (items) => { const t = today(); return items.filter((b) => (b.date || "") >= t).map((b) => ({ id: b.id, date: b.date, moment: b.moment, time: b.time, guests: String(b.guests), status: b.status })); };

async function rateLimit(req, context, bucket, max, seconds) {
  const ip = context?.ip || req.headers.get("x-nf-client-connection-ip") || "0";
  const key = "rl/" + bucket + "/" + crypto.createHash("sha256").update(ip + "|adams").digest("hex").slice(0, 32);
  const now = Date.now();
  let hits = (await readDoc(key, [])) || []; hits = hits.filter((t) => t > now - seconds * 1000);
  if (hits.length >= max) return false;
  hits.push(now); try { await db().setJSON(key, hits); } catch (e) {}
  return true;
}

async function state(admin, tok) {
  const [docs, images, bk] = await Promise.all([Promise.all(PUBLIC_DOCS.map((d) => readDoc(d, null))), readDoc("images", {}), readDoc("bookings", null)]);
  const r = { ok: true, admin, today: today(), images: images || {} };
  PUBLIC_DOCS.forEach((d, i) => (r[d] = docs[i]));
  const b = bookingsDoc(bk); r.slots = slotsFrom(b.items);
  if (admin) { r.csrf = csrfOf(tok); r.bookings = b.items; r.messages = b.msgs; }
  return r;
}

/* ---------- immagini ---------- */
function sniff(buf) {
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return ["jpg", "image/jpeg"];
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return ["png", "image/png"];
  if (buf.slice(0, 4).toString() === "RIFF" && buf.slice(8, 12).toString() === "WEBP") return ["webp", "image/webp"];
  return null;
}
async function serveImage(name) {
  if (!/^[A-Za-z0-9_.-]{1,140}$/.test(name)) return new Response("Not found", { status: 404 });
  const e = await pics().getWithMetadata(name, { type: "arrayBuffer" });
  if (!e || !e.data) return new Response("Not found", { status: 404 });
  return new Response(e.data, { headers: { "Content-Type": (e.metadata && e.metadata.mime) || "image/jpeg", "Cache-Control": "public, max-age=31536000, immutable" } });
}

/* ---------- richieste ---------- */
export default async (req, context) => {
  const url = new URL(req.url);
  try {
    if (req.method === "GET") {
      if (url.searchParams.has("img")) return await serveImage(url.searchParams.get("img"));
      const a = url.searchParams.get("a") || "state";
      if (a === "ping") return json({ ok: true, adams: 1 });
      if (a === "state") { const tok = readToken(req); return json(await state(!!tok, tok)); }
      return fail("Azione sconosciuta.");
    }
    if (req.method !== "POST") return fail("Metodo non ammesso.", 405);
    const raw = await req.text();
    if (raw.length > MAX_IMG * 1.4 + 10000) return fail("Richiesta troppo grande.", 413);
    let inp; try { inp = JSON.parse(raw); } catch (e) { return fail("Richiesta non valida."); }
    if (!inp || typeof inp !== "object") return fail("Richiesta non valida.");
    const tok = readToken(req);
    const requireAdmin = () => { if (!tok) return fail("Accesso riservato.", 403); const h = req.headers.get("x-csrf") || ""; if (!safeEq(h, csrfOf(tok))) return fail("Sessione scaduta, rientra nell'Area riservata.", 403); return null; };

    switch (inp.a) {
      case "login": {
        if (!(await rateLimit(req, context, "login", 8, 900))) return fail("Troppi tentativi. Riprova tra qualche minuto.", 429);
        const pw = typeof inp.password === "string" ? inp.password.trim().toLowerCase() : "";
        if (!pw || !safeEq(pw, password().toLowerCase())) { await new Promise((ok) => setTimeout(ok, 400)); return fail("Password non corretta.", 401); }
        const t = makeToken();
        return json(await state(true, t), 200, { "Set-Cookie": cookieHeader(t, 12 * 3600, req) });
      }
      case "logout":
        return json({ ok: true }, 200, { "Set-Cookie": cookieHeader("", 0, req) });

      case "book": {
        if (!(await rateLimit(req, context, "book", 15, 3600))) return fail("Troppe richieste. Riprova più tardi.", 429);
        const b = inp.b; if (!b || typeof b !== "object") return fail("Prenotazione non valida.");
        if (!isDate(b.date) || b.date < today()) return fail("Data non valida.");
        if (!/^\d\d:\d\d$/.test(b.time || "")) return fail("Orario non valido.");
        if (!MOMENTS.includes(b.moment)) return fail("Momento non valido.");
        const email = s(b.email, 160); if (!isEmail(email)) return fail("Email non valida.");
        const item = { id: newId("b"), created: Date.now(), status: "new", date: b.date, time: b.time, moment: b.moment,
          guests: s(b.guests, 6), name: s(b.name, 80), surname: s(b.surname, 80), email, phone: s(b.phone, 40), requests: s(b.requests, 1500), diet: s(b.diet, 600) };
        if (b.callback && typeof b.callback === "object") item.callback = { date: isDate(b.callback.date) ? b.callback.date : "", time: s(b.callback.time, 10) };
        const set = (await readDoc("settings", {})) || {};
        const slots = await update("bookings", (cur) => {
          const d = bookingsDoc(cur);
          const cap = ((set.cap || {})[item.moment]) || {};
          const dayMax = parseInt(((set.dayCap || {})[item.date] || {})[item.moment] || cap.day || 0, 10) || 0;
          const slotMax = parseInt(cap.slot || 0, 10) || 0;
          let nDay = 0, nSlot = 0;
          for (const x of d.items) { if (x.status === "cancelled" || x.date !== item.date || x.moment !== item.moment) continue; nDay++; if (x.time === item.time) nSlot++; }
          if ((dayMax > 0 && nDay >= dayMax) || (slotMax > 0 && nSlot >= slotMax)) return { ret: null };
          if ((set.closedDays || []).includes(item.date) || (((set.closedMoments || {})[item.date]) || []).includes(item.moment)) return { ret: null };
          d.items.push(item);
          return { value: d, ret: slotsFrom(d.items) };
        });
        if (!slots) return fail("full", 409);
        return json({ ok: true, id: item.id, slots });
      }

      case "message": {
        if (!(await rateLimit(req, context, "msg", 25, 3600))) return fail("Troppe richieste. Riprova più tardi.", 429);
        const m = inp.m; if (!m || typeof m !== "object") return fail("Messaggio non valido.");
        const kind = KINDS.includes(m.kind) ? m.kind : "other";
        const email = s(m.email, 160);
        if ((kind === "newsletter" || kind === "order") && !isEmail(email)) return fail("Email non valida.");
        const x = { id: newId("m"), created: Date.now(), read: false, kind, bookingId: s(m.bookingId, 40), date: isDate(m.date) ? m.date : "", time: s(m.time, 12),
          name: s(m.name, 120), email, phone: s(m.phone, 40), text: s(m.text, 5000), late: s(m.late, 6), guests: s(m.guests, 6), source: s(m.source, 20) };
        if (m.callback && typeof m.callback === "object") x.callback = { date: isDate(m.callback.date) ? m.callback.date : "", time: s(m.callback.time, 10) };
        await update("bookings", (cur) => {
          const d = bookingsDoc(cur);
          if (x.bookingId) { const b = d.items.find((z) => z.id === x.bookingId); if (b) { x.name = ((b.name || "") + " " + (b.surname || "")).trim(); x.email = b.email || ""; if (!x.phone) x.phone = b.phone || ""; x.date = b.date; x.time = b.time; } }
          d.msgs.push(x); if (d.msgs.length > 3000) d.msgs = d.msgs.slice(-3000);
          return { value: d };
        });
        return json({ ok: true });
      }

      case "lookup": {
        if (!(await rateLimit(req, context, "lookup", 20, 3600))) return fail("Troppe richieste. Riprova più tardi.", 429);
        const email = s(inp.email, 160).toLowerCase(); if (!isEmail(email)) return fail("Email non valida.");
        const t = today();
        const list = bookingsDoc(await readDoc("bookings", null)).items.filter((b) => (b.email || "").toLowerCase() === email && b.date >= t && b.status !== "cancelled")
          .map((b) => ({ id: b.id, date: b.date, time: b.time, moment: b.moment, guests: b.guests }));
        return json({ ok: true, list });
      }

      case "save": {
        const no = requireAdmin(); if (no) return no;
        if (!PUBLIC_DOCS.includes(inp.doc)) return fail("Documento sconosciuto.");
        if (!inp.data || typeof inp.data !== "object") return fail("Dati non validi.");
        if (JSON.stringify(inp.data).length > MAX_DOC) return fail("Contenuto troppo grande.");
        await db().setJSON(inp.doc, inp.data);
        return json({ ok: true });
      }

      case "img": {
        const no = requireAdmin(); if (no) return no;
        const key = inp.key;
        if (typeof key !== "string" || !/^(dish|prod|evimg|art)-[A-Za-z0-9_.-]{1,90}$/.test(key)) return fail("Nome immagine non valido.");
        let url2 = "";
        if (inp.src) {
          if (typeof inp.src !== "string" || !/^data:image\/(jpeg|png|webp);base64,/.test(inp.src)) return fail("Formato immagine non valido.");
          const buf = Buffer.from(inp.src.slice(inp.src.indexOf(",") + 1), "base64");
          if (!buf.length || buf.length > MAX_IMG) return fail("Immagine troppo grande.");
          const kind = sniff(buf); if (!kind) return fail("Il file non è un'immagine valida.");
          const name = key.replace(/[^A-Za-z0-9_-]/g, "_") + "-" + crypto.randomBytes(4).toString("hex") + "." + kind[0];
          await pics().set(name, buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length), { metadata: { mime: kind[1] } });
          url2 = "/api?img=" + name;
        }
        const old = await update("images", (cur) => { const im = cur && typeof cur === "object" ? { ...cur } : {}; const prev = im[key] || ""; im[key] = url2; return { value: im, ret: prev }; });
        if (old && old.startsWith("/api?img=")) { try { await pics().delete(old.slice(9)); } catch (e) {} }
        return json({ ok: true, url: url2 });
      }

      case "status": {
        const no = requireAdmin(); if (no) return no;
        const id = s(inp.id, 40), st = inp.status;
        if (!["new", "confirmed", "cancelled"].includes(st)) return fail("Stato non valido.");
        await update("bookings", (cur) => { const d = bookingsDoc(cur); d.items.forEach((b) => { if (b.id === id) b.status = st; }); return { value: d }; });
        return json(await state(true, tok));
      }

      case "read": {
        const no = requireAdmin(); if (no) return no;
        const id = s(inp.id, 40);
        await update("bookings", (cur) => { const d = bookingsDoc(cur); d.msgs.forEach((m) => { if (m.id === id) m.read = true; }); return { value: d }; });
        return json({ ok: true });
      }

      case "state":
        return json(await state(!!tok, tok));
    }
    return fail("Azione sconosciuta.");
  } catch (err) {
    console.error(err);
    return fail("Errore del server. Riprova.", 500);
  }
};
