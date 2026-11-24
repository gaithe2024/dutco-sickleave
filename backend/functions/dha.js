/** Official verification helpers (DHA Sheryan "Verify Documents"). */
// ---------- Official verification: DHA (Sheryan "Verify Documents") ----------
// Public page, no login: barcode number + PIN printed on every DHA document.
// If the page ever shows a human-check / changes format, we fall back to "unavailable"
// (HR then confirms manually on the portal) — we never try to get around such checks.
const DHA_VERIFY_URL = "https://services.dha.gov.ae/sheryan/wps/portal/home/services-professional/online-verification";
const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 DUTCO-SickLeave";

function decodeHtml(s) {
  return String(s || "")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

async function fetchJar(url, opts, jar, maxRedirects = 8) {
  let u = url;
  let o = { ...opts };
  for (let i = 0; i <= maxRedirects; i++) {
    const headers = { "user-agent": BROWSER_UA, "accept-language": "en", ...(o.headers || {}) };
    const ck = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (ck) headers.cookie = ck;
    const res = await fetch(u, { ...o, headers, redirect: "manual", signal: AbortSignal.timeout(20000) });
    const setCookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    for (const sc of setCookies) {
      const kv = sc.split(";")[0];
      const j = kv.indexOf("=");
      if (j > 0) jar.set(kv.slice(0, j).trim(), kv.slice(j + 1).trim());
    }
    const loc = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && loc) {
      u = new URL(loc, u).href;
      o = { method: "GET" };
      continue;
    }
    return { res, url: u };
  }
  throw new Error("too many redirects");
}

async function dhaVerify(barcode, pin) {
  const jar = new Map();
  try {
    const page = await fetchJar(DHA_VERIFY_URL, { method: "GET" }, jar);
    if (!page.res.ok) return { status: "unavailable", note: `page ${page.res.status}` };
    const html = await page.res.text();
    const formTag = html.match(/<form[^>]*id="onlineVerificationFormVO"[^>]*>/i);
    const formBody = html.match(/<form[^>]*id="onlineVerificationFormVO"[^>]*>([\s\S]*?)<\/form>/i);
    const rel = html.match(/verifyDetailsURL\s*=\s*'([^']+)'/);
    if (!formTag || !formBody || !rel) return { status: "unavailable", note: "form not found" };
    const baseM = html.match(/<base[^>]*href="([^"]+)"/i);
    const base = baseM ? new URL(decodeHtml(baseM[1]), page.url).href : page.url;
    const ajaxUrl = new URL(decodeHtml(rel[1]), base).href;

    const params = new URLSearchParams();
    for (const m of formBody[1].matchAll(/<input\b[^>]*>/gi)) {
      const t = m[0];
      const name = (t.match(/\bname="([^"]*)"/i) || [])[1];
      if (!name) continue;
      const type = ((t.match(/\btype="([^"]*)"/i) || [])[1] || "text").toLowerCase();
      if (["submit", "button", "checkbox", "radio", "file", "image"].includes(type)) continue;
      params.set(name, decodeHtml((t.match(/\bvalue="([^"]*)"/i) || [])[1] || ""));
    }
    params.set("barCodeNumber", barcode);
    params.set("pinNumber", pin);

    const post = await fetchJar(ajaxUrl, {
      method: "POST",
      body: params.toString(),
      headers: {
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "x-requested-with": "XMLHttpRequest",
        referer: page.url,
        origin: "https://services.dha.gov.ae",
      },
    }, jar, 0);
    const reply = (await post.res.text()).trim();
    if (/^failed$/i.test(reply)) return { status: "not_found" };
    if (!/^success$/i.test(reply)) return { status: "unavailable", note: `unexpected reply (${post.res.status})` };

    // Record exists. Best effort: read the document details DHA shows next.
    let details = "";
    try {
      const act = (formTag[0].match(/\baction="([^"]+)"/i) || [])[1];
      if (act) {
        const d = await fetchJar(new URL(decodeHtml(act), base).href, {
          method: "POST",
          body: params.toString(),
          headers: { "content-type": "application/x-www-form-urlencoded", referer: page.url },
        }, jar);
        const dh = await d.res.text();
        let txt = dh.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, " ")
          .replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ");
        txt = decodeHtml(txt).replace(/\s+/g, " ");
        const k = txt.search(/Document Information|Verify Documents/i);
        details = txt.slice(Math.max(0, k), Math.max(0, k) + 1500).trim();
      }
    } catch (e) {
      console.warn("dha details", e.message);
    }
    return { status: "verified", details };
  } catch (e) {
    console.error("dhaVerify", e.message);
    return { status: "unavailable", note: e.message };
  }
}

module.exports = { dhaVerify };
