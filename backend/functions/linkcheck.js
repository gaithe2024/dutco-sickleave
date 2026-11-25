/**
 * Opens the verification link printed on a certificate (only on official UAE
 * government / health-authority sites) and reads what the official page says.
 * If the page needs a login, a human-check, or is built entirely by JavaScript,
 * we cannot read it: we return "unclear" and HR opens the link themselves.
 * We never try to get around such checks.
 */
const OFFICIAL_HOST_RE = /(^|\.)(gov\.ae|abudhabi|abudhabi\.ae|tamm\.abudhabi|malaffi\.ae|seha\.ae)$/i;
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 DUTCO-SickLeave";

const NEGATIVE_RE = /(not\s+found|no\s+record|invalid|not\s+valid|does\s+not\s+exist|expired|cancell?ed|revoked|غير\s*صالح|غير\s*موجود|لا\s*توجد|لم\s*يتم\s*العثور|ملغ[اى]ة?|منتهية)/i;

function pageText(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>|<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/\s+/g, " ")
    .trim();
}

const alnum = (s) => String(s || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const words = (s) => String(s || "").toLowerCase().normalize("NFKD").replace(/[^\p{L}\p{N}\s]/gu, " ").split(/\s+/).filter((w) => w.length >= 3);

function dateForms(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(iso || ""));
  if (!m) return [];
  const [, y, mo, d] = m;
  return [`${d}/${mo}/${y}`, `${d}-${mo}-${y}`, `${y}-${mo}-${d}`, `${Number(d)}/${Number(mo)}/${y}`, `${d}.${mo}.${y}`];
}

/** Pure analysis of the official page's text (exported for tests). */
function judgePage(text, cert) {
  const T = text.toLowerCase();
  const tAl = alnum(text);
  const ref = alnum(cert.reference);
  const refFound = ref.length >= 4 && tAl.includes(ref);
  const nameWords = words(cert.patientName);
  const nameFound = nameWords.length > 0 && nameWords.every((w) => T.includes(w));
  const startFound = dateForms(cert.start).some((f) => text.includes(f));
  const endFound = dateForms(cert.end).some((f) => text.includes(f));
  const negative = NEGATIVE_RE.test(text);
  if (negative && !refFound && !nameFound) return { status: "not_found" };
  if (refFound || nameFound) return { status: "verified", refFound, nameFound, datesFound: startFound && endFound };
  return { status: "no_match" }; // readable page, but it does not show this certificate's reference or name
}

async function checkOfficialLink(url, cert) {
  let u;
  try { u = new URL(url); } catch { return { status: "unclear", note: "bad url" }; }
  try {
    for (let hop = 0; hop < 5; hop++) {
      if (u.protocol !== "https:" || !OFFICIAL_HOST_RE.test(u.hostname)) return { status: "unclear", note: "left official site" };
      const res = await fetch(u.href, {
        redirect: "manual",
        headers: { "user-agent": UA, "accept-language": "en,ar;q=0.8", accept: "text/html,application/json;q=0.9,*/*;q=0.5" },
        signal: AbortSignal.timeout(15000),
      });
      const loc = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && loc) { u = new URL(loc, u); continue; }
      const type = res.headers.get("content-type") || "";
      const body = (await res.text()).slice(0, 400000);
      const meta = { http: res.status, type: type.split(";")[0], bytes: body.length };
      if (res.status === 404 || res.status === 410) return { status: "not_found", ...meta };
      if (!res.ok) return { status: "unclear", ...meta };
      if (/captcha|recaptcha|hcaptcha|turnstile/i.test(body)) return { status: "unclear", note: "human check", ...meta };
      const text = /json/i.test(type) ? body.replace(/[{}"\[\],:]/g, " ") : pageText(body);
      if (text.length < 80) return { status: "unclear", note: "page built by JavaScript", ...meta };
      return { ...judgePage(text, cert), ...meta };
    }
    return { status: "unclear", note: "too many redirects" };
  } catch (e) {
    return { status: "unclear", note: e.message };
  }
}

module.exports = { checkOfficialLink, judgePage, OFFICIAL_HOST_RE };
