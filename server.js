// Umsatzplanner online: ein Konto pro Kunde, Daten pro Kunde in SQLite, KI über den Schlüssel des Betreibers.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import vm from "node:vm";
import { promisify } from "node:util";
import { DatabaseSync } from "node:sqlite";
import Anthropic from "@anthropic-ai/sdk";

const HIER = import.meta.dirname;
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || (fs.existsSync("/data") ? "/data" : path.join(HIER, "data"));
const MAX_GERAETE = Math.max(1, Number(process.env.MAX_GERAETE || 2));
const KI_LIMIT_TAG = Math.max(0, Number(process.env.KI_LIMIT_TAG || 20));
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";
const SITZUNG_TAGE = 180;
const MAX_DATEN = 8 * 1024 * 1024;   // gespeicherter Datenstand
const MAX_KI = 32 * 1024 * 1024;     // Fotos/PDFs für die KI
const COOKIE = "up_s", ADMIN_COOKIE = "up_admin";

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, "umsatzplanner.db"));
db.exec(`
PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS kunden(
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, lokal TEXT NOT NULL DEFAULT '',
  pw_hash TEXT NOT NULL, gesperrt INTEGER NOT NULL DEFAULT 0, notiz TEXT NOT NULL DEFAULT '',
  erstellt TEXT NOT NULL, zuletzt TEXT);
CREATE TABLE IF NOT EXISTS daten(
  kunde_id TEXT PRIMARY KEY REFERENCES kunden(id) ON DELETE CASCADE,
  version INTEGER NOT NULL, json TEXT NOT NULL, geaendert TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sicherungen(
  kunde_id TEXT NOT NULL REFERENCES kunden(id) ON DELETE CASCADE, tag TEXT NOT NULL, json TEXT NOT NULL,
  PRIMARY KEY(kunde_id, tag));
CREATE TABLE IF NOT EXISTS sitzungen(
  token_hash TEXT PRIMARY KEY, kunde_id TEXT NOT NULL REFERENCES kunden(id) ON DELETE CASCADE,
  erstellt TEXT NOT NULL, zuletzt TEXT NOT NULL, geraet TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS sitzungen_kunde ON sitzungen(kunde_id);
CREATE TABLE IF NOT EXISTS ki_nutzung(
  kunde_id TEXT NOT NULL REFERENCES kunden(id) ON DELETE CASCADE, tag TEXT NOT NULL, anzahl INTEGER NOT NULL,
  PRIMARY KEY(kunde_id, tag));
CREATE TABLE IF NOT EXISTS admin_sitzungen(token_hash TEXT PRIMARY KEY, erstellt TEXT NOT NULL);
`);

/* ---------- Helfer ---------- */
const jetzt = () => new Date().toISOString();
const heute = () => new Date().toLocaleDateString("sv-SE", { timeZone: "Europe/Vienna" }); // JJJJ-MM-TT
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const neuesToken = () => crypto.randomBytes(32).toString("base64url");
const scrypt = promisify(crypto.scrypt);
async function pwHash(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString("base64")}$${h.toString("base64")}`;
}
async function pwPruefen(pw, gespeichert) {
  const [art, salt, hash] = String(gespeichert).split("$");
  if (art !== "scrypt" || !salt || !hash) return false;
  const h = await scrypt(pw, Buffer.from(salt, "base64"), 64, { N: 16384, r: 8, p: 1 });
  const soll = Buffer.from(hash, "base64");
  return soll.length === h.length && crypto.timingSafeEqual(soll, h);
}
const DUMMY_HASH = await pwHash(crypto.randomBytes(12).toString("hex")); // gleiche Rechenzeit bei unbekanntem Namen
function passwortErzeugen() {
  const z = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const b = crypto.randomBytes(12);
  return [...b].map(x => z[x % z.length]).join("").replace(/(.{4})(?=.)/g, "$1-");
}
function cookies(req) {
  const c = {};
  String(req.headers.cookie || "").split(";").forEach(p => { const i = p.indexOf("="); if (i > 0) c[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return c;
}
const istHttps = req => String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
function setCookie(res, req, name, wert, maxAge, pfad = "/") {
  const teile = [`${name}=${encodeURIComponent(wert)}`, `Path=${pfad}`, "HttpOnly", "SameSite=Lax", `Max-Age=${maxAge}`];
  if (istHttps(req)) teile.push("Secure");
  const alt = res.getHeader("Set-Cookie"); const liste = alt ? [].concat(alt) : [];
  res.setHeader("Set-Cookie", [...liste, teile.join("; ")]);
}
const ipVon = req => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

const SICHERHEIT = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
};
function senden(res, status, body, typ = "application/json; charset=utf-8", extra = {}) {
  const daten = typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, { ...SICHERHEIT, "Content-Type": typ, "Cache-Control": "no-store", ...extra });
  res.end(daten);
}
const json = (res, status, obj) => senden(res, status, obj);
const umleiten = (res, ort) => { res.writeHead(302, { ...SICHERHEIT, Location: ort, "Cache-Control": "no-store" }); res.end(); };

class Fehler extends Error { constructor(status, text) { super(text); this.status = status; } }
function koerper(req, max) {
  return new Promise((ok, nein) => {
    const laenge = Number(req.headers["content-length"] || 0);
    if (laenge > max) return nein(new Fehler(413, "Zu groß"));
    const teile = []; let n = 0;
    req.on("data", c => { n += c.length; if (n > max) { nein(new Fehler(413, "Zu groß")); req.destroy(); } else teile.push(c); });
    req.on("end", () => { try { ok(n ? JSON.parse(Buffer.concat(teile).toString("utf8")) : {}); } catch { nein(new Fehler(400, "Ungültige Anfrage")); } });
    req.on("error", nein);
  });
}

/* ---------- einfache Bremse gegen Passwort-Raten ---------- */
const versuche = new Map(); // schluessel -> [zeitstempel…]
function gebremst(schluessel, max = 10, fensterMs = 15 * 60e3) {
  const t = Date.now(); const l = (versuche.get(schluessel) || []).filter(x => t - x < fensterMs);
  versuche.set(schluessel, l); return l.length >= max;
}
function fehlversuch(schluessel) { const l = versuche.get(schluessel) || []; l.push(Date.now()); versuche.set(schluessel, l); }
setInterval(() => { const t = Date.now(); for (const [k, l] of versuche) if (!l.some(x => t - x < 15 * 60e3)) versuche.delete(k); }, 60e3).unref();

/* ---------- Sitzungen ---------- */
const q = {
  kundeNachName: db.prepare("SELECT * FROM kunden WHERE name = ?"),
  kunde: db.prepare("SELECT * FROM kunden WHERE id = ?"),
  sitzung: db.prepare("SELECT s.token_hash, s.zuletzt, k.* FROM sitzungen s JOIN kunden k ON k.id = s.kunde_id WHERE s.token_hash = ?"),
  sitzungZuletzt: db.prepare("UPDATE sitzungen SET zuletzt = ? WHERE token_hash = ?"),
  sitzungNeu: db.prepare("INSERT INTO sitzungen(token_hash, kunde_id, erstellt, zuletzt, geraet, ip) VALUES (?,?,?,?,?,?)"),
  sitzungenVon: db.prepare("SELECT token_hash FROM sitzungen WHERE kunde_id = ? ORDER BY zuletzt DESC"),
  sitzungWeg: db.prepare("DELETE FROM sitzungen WHERE token_hash = ?"),
  sitzungenWeg: db.prepare("DELETE FROM sitzungen WHERE kunde_id = ?"),
  sitzungenAndereWeg: db.prepare("DELETE FROM sitzungen WHERE kunde_id = ? AND token_hash <> ?"),
  sitzungenAlt: db.prepare("DELETE FROM sitzungen WHERE zuletzt < ?"),
  kundeZuletzt: db.prepare("UPDATE kunden SET zuletzt = ? WHERE id = ?"),
  daten: db.prepare("SELECT version, json FROM daten WHERE kunde_id = ?"),
  datenVersion: db.prepare("SELECT version FROM daten WHERE kunde_id = ?"),
  datenSetzen: db.prepare("INSERT INTO daten(kunde_id, version, json, geaendert) VALUES (?,?,?,?) ON CONFLICT(kunde_id) DO UPDATE SET version = excluded.version, json = excluded.json, geaendert = excluded.geaendert"),
  sicherungNeu: db.prepare("INSERT OR IGNORE INTO sicherungen(kunde_id, tag, json) VALUES (?,?,?)"),
  sicherungenAlt: db.prepare("DELETE FROM sicherungen WHERE tag < ?"),
  kiHeute: db.prepare("SELECT anzahl FROM ki_nutzung WHERE kunde_id = ? AND tag = ?"),
  kiZaehlen: db.prepare("INSERT INTO ki_nutzung(kunde_id, tag, anzahl) VALUES (?,?,1) ON CONFLICT(kunde_id, tag) DO UPDATE SET anzahl = anzahl + 1"),
  adminSitzung: db.prepare("SELECT * FROM admin_sitzungen WHERE token_hash = ? AND erstellt > ?"),
  adminSitzungNeu: db.prepare("INSERT INTO admin_sitzungen(token_hash, erstellt) VALUES (?,?)"),
  adminSitzungWeg: db.prepare("DELETE FROM admin_sitzungen WHERE token_hash = ?"),
};
function aufraeumen() {
  q.sitzungenAlt.run(new Date(Date.now() - SITZUNG_TAGE * 864e5).toISOString());
  q.sicherungenAlt.run(new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10));
  db.prepare("DELETE FROM admin_sitzungen WHERE erstellt < ?").run(new Date(Date.now() - 864e5).toISOString());
}
aufraeumen(); setInterval(aufraeumen, 3600e3).unref();

function angemeldet(req) {
  const t = cookies(req)[COOKIE]; if (!t) return null;
  const s = q.sitzung.get(sha(t));
  if (!s || s.gesperrt) return null;
  if (Date.now() - Date.parse(s.zuletzt) > 5 * 60e3) { q.sitzungZuletzt.run(jetzt(), s.token_hash); q.kundeZuletzt.run(jetzt(), s.id); }
  return s;
}
function geraetName(ua) {
  ua = String(ua || "");
  const os = /iPad/.test(ua) ? "iPad" : /iPhone/.test(ua) ? "iPhone" : /Android/.test(ua) ? "Android" : /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "Mac" : /Linux/.test(ua) ? "Linux" : "Gerät";
  const br = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "";
  return (os + (br ? " · " + br : "")).slice(0, 60);
}
function sitzungAnlegen(req, res, kunde) {
  // höchstens MAX_GERAETE: die am längsten nicht benutzten fliegen raus
  const alle = q.sitzungenVon.all(kunde.id);
  alle.slice(MAX_GERAETE - 1).forEach(s => q.sitzungWeg.run(s.token_hash));
  const t = neuesToken();
  q.sitzungNeu.run(sha(t), kunde.id, jetzt(), jetzt(), geraetName(req.headers["user-agent"]), ipVon(req).slice(0, 64));
  q.kundeZuletzt.run(jetzt(), kunde.id);
  setCookie(res, req, COOKIE, t, SITZUNG_TAGE * 86400);
}
function istAdmin(req) {
  const t = cookies(req)[ADMIN_COOKIE];
  return !!(t && ADMIN_PASSWORD && q.adminSitzung.get(sha(t), new Date(Date.now() - 12 * 3600e3).toISOString()));
}
// Schutz gegen fremde Seiten, die im Namen des Nutzers Anfragen schicken (CSRF)
function csrfOk(req) {
  if (req.headers["x-umsatzplanner"] !== "1") return false;
  const herkunft = req.headers.origin;
  if (herkunft) { try { if (new URL(herkunft).host !== req.headers.host) return false; } catch { return false; } }
  return true;
}

/* ---------- Seiten ---------- */
const PUBLIC = path.join(HIER, "public");
const lies = f => fs.readFileSync(path.join(PUBLIC, f), "utf8");
let APP = lies("index.html"), LOGIN = lies("login.html"), ADMIN = lies("admin.html");
if (process.env.NODE_ENV === "development") { // beim Entwickeln immer frisch lesen
  setInterval(() => { APP = lies("index.html"); LOGIN = lies("login.html"); ADMIN = lies("admin.html"); KI = kiLaden(); }, 1000).unref();
}
// gemeinsamer KI-Block aus der App (Schema + Auftrag), damit Browser und Server dasselbe verwenden
function kiLaden() {
  const m = APP.match(/\/\* KI-GEMEINSAM-START[\s\S]*?\*\/([\s\S]*?)\/\* KI-GEMEINSAM-ENDE \*\//);
  if (!m) throw new Error("KI-Block in index.html nicht gefunden");
  const ctx = {}; vm.createContext(ctx);
  vm.runInContext(m[1] + "\n;globalThis.__ki={KI_MODELL,KI_SCHEMA,kiAuftrag};", ctx);
  return ctx.__ki;
}
let KI = kiLaden();

const skriptSicher = s => JSON.stringify(s).replace(/</g, "\\u003c");
function appSeite(kunde) {
  const d = q.daten.get(kunde.id);
  const start = { kunde: { id: kunde.id, name: kunde.name, lokal: kunde.lokal }, version: d ? d.version : 0, daten: d ? JSON.parse(d.json) : null, maxGeraete: MAX_GERAETE };
  return APP.replace(/<html([^>]*)>/, '<html$1 data-online>')
    .replace("<script>", `<script>window.UMSATZ_START=${skriptSicher(start)};</script>\n<script>`);
}

/* ---------- KI ---------- */
const ki = ANTHROPIC_API_KEY ? new Anthropic({ apiKey: ANTHROPIC_API_KEY, timeout: 5 * 60e3, maxRetries: 2 }) : null;
const kiLaeuft = new Set();
const BILD_TYPEN = ["image/jpeg", "image/png", "image/webp", "image/gif"];
function bloeckePruefen(bloecke) {
  if (!Array.isArray(bloecke) || bloecke.length > 20) throw new Fehler(400, "Bitte höchstens 20 Dateien auf einmal.");
  return bloecke.map(b => {
    const s = b && b.source;
    if (!s || s.type !== "base64" || typeof s.data !== "string" || !/^[A-Za-z0-9+/=]+$/.test(s.data)) throw new Fehler(400, "Eine Datei konnte nicht gelesen werden.");
    if (b.type === "image" && BILD_TYPEN.includes(s.media_type)) return { type: "image", source: { type: "base64", media_type: s.media_type, data: s.data } };
    if (b.type === "document" && s.media_type === "application/pdf") return { type: "document", source: { type: "base64", media_type: "application/pdf", data: s.data } };
    throw new Fehler(400, "Nur Fotos (JPG, PNG) und PDFs sind möglich.");
  });
}
async function kiAnfrage(kunde, body) {
  if (!ki) throw new Fehler(503, "Die KI ist auf diesem Server noch nicht eingerichtet. Bitte beim Anbieter melden.");
  const genutzt = (q.kiHeute.get(kunde.id, heute()) || { anzahl: 0 }).anzahl;
  if (genutzt >= KI_LIMIT_TAG) throw new Fehler(429, `Für heute sind alle ${KI_LIMIT_TAG} KI-Durchgänge aufgebraucht. Morgen geht es wieder, oder nutz bis dahin die Excel-Vorlage.`);
  if (kiLaeuft.has(kunde.id)) throw new Fehler(429, "Es läuft schon ein Durchgang. Bitte warten, bis er fertig ist.");
  const modus = body.modus === "rezepte" ? "rezepte" : "karte";
  const text = typeof body.text === "string" ? body.text.trim().slice(0, 60000) : "";
  const bloecke = bloeckePruefen(body.bloecke || []);
  if (!bloecke.length && !text) throw new Fehler(400, "Bitte Foto oder PDF wählen oder Text einfügen.");
  const d = q.daten.get(kunde.id); let stand = {};
  try { stand = d ? JSON.parse(d.json) : {}; } catch { }
  const zutaten = (Array.isArray(stand.zutaten) ? stand.zutaten : []).map(z => `${String(z.name).slice(0, 80)} (${String(z.einheit).slice(0, 10)})`);
  const produkte = (Array.isArray(stand.produkte) ? stand.produkte : []).map(p => String(p.name).slice(0, 80));
  const auftrag = KI.kiAuftrag({ modus, schaetzen: !!body.schaetzen, mitText: !!text, zutaten, produkte });
  const inhalt = [...bloecke]; if (text) inhalt.push({ type: "text", text: "Text:\n" + text }); inhalt.push({ type: "text", text: auftrag });
  kiLaeuft.add(kunde.id);
  try {
    const antwort = await ki.beta.messages.stream({
      model: KI.KI_MODELL, max_tokens: 16000,
      betas: ["server-side-fallback-2026-07-01"], fallbacks: "default",
      output_config: { effort: "medium", format: { type: "json_schema", schema: KI.KI_SCHEMA } },
      messages: [{ role: "user", content: inhalt }],
    }).finalMessage();
    if (antwort.stop_reason !== "refusal") q.kiZaehlen.run(kunde.id, heute());
    return { stop_reason: antwort.stop_reason, content: antwort.content.filter(b => b.type === "text").map(b => ({ type: "text", text: b.text })) };
  } catch (e) {
    if (e instanceof Fehler) throw e;
    const st = e && e.status;
    console.error("KI-Fehler", st || "", e && e.message);
    if (st === 413) throw new Fehler(413, "Die Dateien sind zu groß. Bitte weniger oder kleinere Seiten hochladen.");
    if (st === 400) throw new Fehler(400, "Die KI konnte die Dateien nicht verarbeiten. Bitte ein anderes Foto oder PDF versuchen.");
    if (st === 429 || st === 529 || (st >= 500)) throw new Fehler(503, "Die KI ist gerade ausgelastet. Bitte in ein paar Minuten nochmal versuchen.");
    throw new Fehler(502, "Die KI ist gerade nicht erreichbar. Bitte später nochmal versuchen.");
  } finally { kiLaeuft.delete(kunde.id); }
}

/* ---------- Datenprüfung ---------- */
function datenPruefen(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) throw new Fehler(400, "Ungültige Daten");
  for (const k of ["zutaten", "produkte", "verkaeufe"]) if (!Array.isArray(d[k])) throw new Fehler(400, "Ungültige Daten");
  return d;
}

/* ---------- Admin ---------- */
function kundenListe() {
  const t = heute();
  return db.prepare(`SELECT k.id, k.name, k.lokal, k.gesperrt, k.notiz, k.erstellt, k.zuletzt,
      (SELECT COUNT(*) FROM sitzungen s WHERE s.kunde_id = k.id) AS geraete,
      (SELECT anzahl FROM ki_nutzung n WHERE n.kunde_id = k.id AND n.tag = ?) AS ki_heute,
      (SELECT COALESCE(SUM(anzahl),0) FROM ki_nutzung n WHERE n.kunde_id = k.id AND n.tag >= ?) AS ki_monat,
      (SELECT geaendert FROM daten d WHERE d.kunde_id = k.id) AS geaendert,
      (SELECT LENGTH(json) FROM daten d WHERE d.kunde_id = k.id) AS groesse
    FROM kunden k ORDER BY k.erstellt DESC`).all(t, t.slice(0, 8) + "01")
    .map(k => ({ ...k, sitzungen: db.prepare("SELECT geraet, ip, erstellt, zuletzt FROM sitzungen WHERE kunde_id = ? ORDER BY zuletzt DESC").all(k.id),
      sicherungen: db.prepare("SELECT tag FROM sicherungen WHERE kunde_id = ? ORDER BY tag DESC").all(k.id).map(x => x.tag) }));
}
const nameOk = n => typeof n === "string" && /^[A-Za-z0-9._@+-]{3,60}$/.test(n.trim());

async function admin(req, res, url) {
  const p = url.pathname;
  if (p === "/admin" && req.method === "GET") return senden(res, 200, ADMIN, "text/html; charset=utf-8");
  if (p === "/api/admin/login" && req.method === "POST") {
    if (!csrfOk(req)) return json(res, 403, { fehler: "Ungültige Anfrage" });
    if (!ADMIN_PASSWORD) return json(res, 503, { fehler: "ADMIN_PASSWORD ist auf dem Server nicht gesetzt." });
    const ip = ipVon(req);
    if (gebremst("admin:" + ip, 5)) return json(res, 429, { fehler: "Zu viele Versuche. Bitte 15 Minuten warten." });
    const b = await koerper(req, 10e3);
    const a = Buffer.from(sha(String(b.passwort || ""))), z = Buffer.from(sha(ADMIN_PASSWORD));
    if (!crypto.timingSafeEqual(a, z)) { fehlversuch("admin:" + ip); return json(res, 401, { fehler: "Passwort falsch" }); }
    const t = neuesToken(); q.adminSitzungNeu.run(sha(t), jetzt());
    setCookie(res, req, ADMIN_COOKIE, t, 12 * 3600);
    return json(res, 200, { ok: true });
  }
  if (!istAdmin(req)) return json(res, 401, { fehler: "Nicht angemeldet" });
  if (req.method !== "GET" && !csrfOk(req)) return json(res, 403, { fehler: "Ungültige Anfrage" });
  if (p === "/api/admin/kunden" && req.method === "GET") return json(res, 200, { kunden: kundenListe(), maxGeraete: MAX_GERAETE, kiLimit: KI_LIMIT_TAG, kiAktiv: !!ki });
  if (p === "/api/admin/logout" && req.method === "POST") { q.adminSitzungWeg.run(sha(cookies(req)[ADMIN_COOKIE] || "")); setCookie(res, req, ADMIN_COOKIE, "", 0); return json(res, 200, { ok: true }); }
  if (p === "/api/admin/kunden" && req.method === "POST") {
    const b = await koerper(req, 10e3);
    const name = String(b.name || "").trim();
    if (!nameOk(name)) return json(res, 400, { fehler: "Benutzername: 3 bis 60 Zeichen, nur Buchstaben, Ziffern und . _ - @ +" });
    if (q.kundeNachName.get(name)) return json(res, 409, { fehler: "Diesen Benutzernamen gibt es schon." });
    const pw = passwortErzeugen(), id = crypto.randomUUID();
    db.prepare("INSERT INTO kunden(id, name, lokal, pw_hash, notiz, erstellt) VALUES (?,?,?,?,?,?)")
      .run(id, name, String(b.lokal || "").trim().slice(0, 100), await pwHash(pw), String(b.notiz || "").slice(0, 500), jetzt());
    return json(res, 200, { id, name, passwort: pw });
  }
  const m = p.match(/^\/api\/admin\/kunden\/([0-9a-f-]{36})(?:\/([a-z-]+))?(?:\/(\d{4}-\d{2}-\d{2}))?$/);
  if (!m) return json(res, 404, { fehler: "Nicht gefunden" });
  const k = q.kunde.get(m[1]); if (!k) return json(res, 404, { fehler: "Kunde nicht gefunden" });
  const aktion = m[2] || "";
  if (req.method === "POST" && aktion === "passwort") {
    const pw = passwortErzeugen();
    db.prepare("UPDATE kunden SET pw_hash = ? WHERE id = ?").run(await pwHash(pw), k.id); q.sitzungenWeg.run(k.id);
    return json(res, 200, { name: k.name, passwort: pw });
  }
  if (req.method === "POST" && aktion === "abmelden") { q.sitzungenWeg.run(k.id); return json(res, 200, { ok: true }); }
  if (req.method === "POST" && aktion === "sperren") {
    const b = await koerper(req, 1e3); const g = b.gesperrt ? 1 : 0;
    db.prepare("UPDATE kunden SET gesperrt = ? WHERE id = ?").run(g, k.id); if (g) q.sitzungenWeg.run(k.id);
    return json(res, 200, { ok: true });
  }
  if (req.method === "POST" && aktion === "bearbeiten") {
    const b = await koerper(req, 10e3);
    db.prepare("UPDATE kunden SET lokal = ?, notiz = ? WHERE id = ?").run(String(b.lokal ?? k.lokal).trim().slice(0, 100), String(b.notiz ?? k.notiz).slice(0, 500), k.id);
    return json(res, 200, { ok: true });
  }
  if (req.method === "GET" && aktion === "daten") {
    const d = m[3] ? db.prepare("SELECT json FROM sicherungen WHERE kunde_id = ? AND tag = ?").get(k.id, m[3]) : q.daten.get(k.id);
    if (!d) return json(res, 404, { fehler: "Keine Daten" });
    return senden(res, 200, d.json, "application/json; charset=utf-8", { "Content-Disposition": `attachment; filename="umsatzplanner-${k.name.replace(/[^A-Za-z0-9._-]/g, "_")}-${m[3] || heute()}.json"` });
  }
  if (req.method === "POST" && aktion === "wiederherstellen" && m[3]) {
    const s = db.prepare("SELECT json FROM sicherungen WHERE kunde_id = ? AND tag = ?").get(k.id, m[3]);
    if (!s) return json(res, 404, { fehler: "Sicherung nicht gefunden" });
    const alt = q.daten.get(k.id);
    if (alt) q.sicherungNeu.run(k.id, heute(), alt.json);
    q.datenSetzen.run(k.id, (alt ? alt.version : 0) + 1, s.json, jetzt());
    return json(res, 200, { ok: true });
  }
  if (req.method === "DELETE" && !aktion) {
    const b = await koerper(req, 1e3);
    if (String(b.bestaetigung || "") !== k.name) return json(res, 400, { fehler: "Zum Löschen den Benutzernamen eintippen." });
    db.prepare("DELETE FROM kunden WHERE id = ?").run(k.id);
    return json(res, 200, { ok: true });
  }
  return json(res, 404, { fehler: "Nicht gefunden" });
}

/* ---------- Router ---------- */
async function verarbeiten(req, res) {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  if (p === "/health") return senden(res, 200, "ok", "text/plain");
  if (p === "/admin" || p.startsWith("/api/admin/")) return admin(req, res, url);
  if (p === "/favicon.ico") { res.writeHead(204); return res.end(); }

  if (p === "/" && req.method === "GET") {
    const k = angemeldet(req); if (!k) return umleiten(res, "/login");
    return senden(res, 200, appSeite(k), "text/html; charset=utf-8");
  }
  if (p === "/login" && req.method === "GET") {
    if (angemeldet(req)) return umleiten(res, "/");
    return senden(res, 200, LOGIN, "text/html; charset=utf-8");
  }
  if (p === "/api/login" && req.method === "POST") {
    if (!csrfOk(req)) return json(res, 403, { fehler: "Ungültige Anfrage" });
    const b = await koerper(req, 10e3);
    const name = String(b.name || "").trim(), pw = String(b.passwort || "");
    const ip = ipVon(req);
    if (gebremst("ip:" + ip, 30) || gebremst("name:" + name.toLowerCase(), 10)) return json(res, 429, { fehler: "Zu viele Versuche. Bitte 15 Minuten warten." });
    const k = name ? q.kundeNachName.get(name) : null;
    const ok = await pwPruefen(pw, k ? k.pw_hash : DUMMY_HASH);
    if (!k || !ok) { fehlversuch("ip:" + ip); fehlversuch("name:" + name.toLowerCase()); return json(res, 401, { fehler: "Benutzername oder Passwort stimmt nicht." }); }
    if (k.gesperrt) return json(res, 403, { fehler: "Dieser Zugang ist gesperrt. Bitte beim Anbieter melden." });
    sitzungAnlegen(req, res, k);
    return json(res, 200, { ok: true });
  }

  if (!p.startsWith("/api/")) return senden(res, 404, "Nicht gefunden", "text/plain; charset=utf-8");
  const k = angemeldet(req);
  if (!k) return json(res, 401, {});
  if (req.method !== "GET" && !csrfOk(req)) return json(res, 403, { fehler: "Ungültige Anfrage" });
  const meinToken = sha(cookies(req)[COOKIE] || "");

  if (p === "/api/daten" && req.method === "GET") {
    const v = q.datenVersion.get(k.id), version = v ? v.version : 0;
    if (url.searchParams.get("seit") === String(version)) { res.writeHead(204, { ...SICHERHEIT, "Cache-Control": "no-store" }); return res.end(); }
    const d = q.daten.get(k.id);
    return senden(res, 200, `{"version":${version},"daten":${d ? d.json : "null"}}`);
  }
  if (p === "/api/daten" && req.method === "PUT") {
    const b = await koerper(req, MAX_DATEN + 1e5);
    const daten = datenPruefen(b.daten);
    const text = JSON.stringify(daten);
    if (text.length > MAX_DATEN) return json(res, 413, { fehler: "Zu viele Daten" });
    let ergebnis;
    db.exec("BEGIN IMMEDIATE");
    try {
      const alt = q.daten.get(k.id), version = alt ? alt.version : 0;
      if (Number(b.version) !== version) ergebnis = [409, `{"version":${version},"daten":${alt ? alt.json : "null"}}`];
      else {
        if (alt) q.sicherungNeu.run(k.id, heute(), alt.json); // erster Stand des Tages bleibt als Sicherung
        q.datenSetzen.run(k.id, version + 1, text, jetzt());
        ergebnis = [200, `{"version":${version + 1}}`];
      }
      db.exec("COMMIT");
    } catch (e) { db.exec("ROLLBACK"); throw e; }
    return senden(res, ergebnis[0], ergebnis[1]);
  }
  if (p === "/api/ki/kontingent" && req.method === "GET") {
    const n = (q.kiHeute.get(k.id, heute()) || { anzahl: 0 }).anzahl;
    return json(res, 200, { limit: KI_LIMIT_TAG, rest: Math.max(0, KI_LIMIT_TAG - n), aktiv: !!ki });
  }
  if (p === "/api/ki" && req.method === "POST") {
    const b = await koerper(req, MAX_KI);
    return json(res, 200, await kiAnfrage(k, b));
  }
  if (p === "/api/logout" && req.method === "POST") { q.sitzungWeg.run(meinToken); setCookie(res, req, COOKIE, "", 0); return json(res, 200, { ok: true }); }
  if (p === "/api/logout-andere" && req.method === "POST") { q.sitzungenAndereWeg.run(k.id, meinToken); return json(res, 200, { ok: true }); }
  if (p === "/api/passwort" && req.method === "POST") {
    const b = await koerper(req, 10e3);
    if (gebremst("pw:" + k.id, 10)) return json(res, 429, { fehler: "Zu viele Versuche. Bitte 15 Minuten warten." });
    if (!(await pwPruefen(String(b.alt || ""), k.pw_hash))) { fehlversuch("pw:" + k.id); return json(res, 400, { fehler: "Das aktuelle Passwort stimmt nicht." }); }
    const neu = String(b.neu || "");
    if (neu.length < 8 || neu.length > 200) return json(res, 400, { fehler: "Das neue Passwort braucht mindestens 8 Zeichen." });
    db.prepare("UPDATE kunden SET pw_hash = ? WHERE id = ?").run(await pwHash(neu), k.id);
    q.sitzungenAndereWeg.run(k.id, meinToken);
    return json(res, 200, { ok: true });
  }
  return json(res, 404, { fehler: "Nicht gefunden" });
}

const server = http.createServer((req, res) => {
  verarbeiten(req, res).catch(e => {
    if (!(e instanceof Fehler)) console.error(e);
    if (res.headersSent) return res.end();
    json(res, e instanceof Fehler ? e.status : 500, { fehler: e instanceof Fehler ? e.message : "Interner Fehler. Bitte nochmal versuchen." });
  });
});
server.requestTimeout = 6 * 60e3;
server.listen(PORT, () => console.log(`Umsatzplanner läuft auf Port ${PORT} · Daten in ${DATA_DIR} · KI ${ki ? "aktiv" : "AUS (ANTHROPIC_API_KEY fehlt)"} · Admin ${ADMIN_PASSWORD ? "aktiv" : "AUS (ADMIN_PASSWORD fehlt)"}`));
const ende = () => { server.close(); try { db.close(); } catch { } process.exit(0); };
process.on("SIGTERM", ende); process.on("SIGINT", ende);
