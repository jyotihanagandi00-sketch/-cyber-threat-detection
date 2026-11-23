import { useState, useEffect, useRef, useCallback } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line,
} from "recharts";
import axios from "axios";

const API = "http://127.0.0.1:8000";
const GREEN = "#5ff0a0", RED = "#ff5a5a", ORANGE = "#ff6a2b";
const AMBER = "#ffb02e", VIOLET = "#9b8cff", BLUE = "#5ec8ff";
const PIPES = ["URL Click", "Extension", "Features", "ML Ensemble", "Gemini AI", "Alert / Block"];

const css = `
*{box-sizing:border-box}
body{margin:0;background:#140503}
@keyframes drift{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(50px,-30px) scale(1.12)}}
@keyframes sweep{to{transform:rotate(360deg)}}
@keyframes blip{0%{transform:scale(.6);opacity:1}100%{transform:scale(2.6);opacity:0}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
@keyframes fade{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.bg div{position:fixed;border-radius:50%;pointer-events:none}
.panel{position:relative;z-index:1;width:calc(100% - 48px);max-width:1500px;margin:24px auto;padding:26px 30px;
 border-radius:34px;background:rgba(9,7,7,.78);border:1px solid rgba(255,255,255,.16);
 backdrop-filter:blur(26px);box-shadow:0 30px 80px rgba(0,0,0,.55);display:flex;flex-direction:column;gap:16px}
.card{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.11);border-radius:22px;padding:18px 22px;position:relative;overflow:hidden;min-width:0}
.glow{background:radial-gradient(circle at 85% 100%,rgba(255,92,31,.45),transparent 60%),rgba(255,255,255,.05)}
.lbl{font-size:15px;font-weight:700;color:#fff}
.sub{font-size:13px;color:#cfcfd6}
.pill{font-size:12px;font-weight:700;padding:4px 12px;border-radius:99px;letter-spacing:.06em;text-align:center;white-space:nowrap}
.chip{font-size:13px;padding:4px 12px;border-radius:8px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);color:#e4e4ea}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.gA{display:grid;grid-template-columns:330px 1fr;gap:14px}
.gB,.gC{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.row{display:grid;grid-template-columns:1fr 110px 150px 80px;align-items:center;gap:12px;padding:9px 0;border-top:1px solid rgba(255,255,255,.08);font-family:Consolas,monospace;font-size:14px;cursor:pointer;animation:fade .35s ease}
.bar{height:8px;border-radius:4px;background:rgba(255,255,255,.1);overflow:hidden}
input:focus{outline:none;border-color:rgba(255,106,43,.7)!important}
button{cursor:pointer}
@media(max-width:1150px){.g4,.gA,.gB,.gC{grid-template-columns:1fr}}
`;

const pillStyle = (v) =>
  v === "SAFE"
    ? { background: "rgba(95,240,160,.15)", color: GREEN }
    : { background: "rgba(255,90,90,.2)", color: "#ff8a80" };

const place = (u = "") => {
  let h = 0;
  for (const c of u) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const a = ((h % 360) * Math.PI) / 180;
  const r = 22 + ((h >>> 9) % 55);
  return { x: 50 + r * Math.cos(a) * 0.9, y: 50 + r * Math.sin(a) * 0.9 };
};

function Gauge({ pct }) {
  return (
    <svg viewBox="0 0 200 118" width="100%" style={{ maxHeight: 175 }}>
      <defs>
        <linearGradient id="ga" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor={AMBER} />
          <stop offset="1" stopColor="#ff4d3a" />
        </linearGradient>
      </defs>
      <path d="M20 104 A80 80 0 0 1 180 104" fill="none" stroke="rgba(255,255,255,.12)" strokeWidth="16" strokeLinecap="round" />
      <path d="M20 104 A80 80 0 0 1 180 104" fill="none" stroke="url(#ga)" strokeWidth="16" strokeLinecap="round"
        pathLength="100" strokeDasharray={`${Math.max(pct, 0.5)} 100`} />
      <text x="100" y="92" textAnchor="middle" fill="#fff" fontSize="32" fontWeight="800">{pct}%</text>
      <text x="100" y="112" textAnchor="middle" fill="#cfcfd6" fontSize="12">malicious of all scans</text>
    </svg>
  );
}

function Radar({ blips }) {
  return (
    <div style={{ position: "relative", width: 190, height: 190, borderRadius: "50%", margin: "8px auto",
      border: "1px solid rgba(255,255,255,.25)", overflow: "hidden",
      background: "repeating-radial-gradient(circle,transparent 0 30px,rgba(255,255,255,.14) 30px 31px)" }}>
      <div style={{ position: "absolute", inset: 0, borderRadius: "50%",
        background: "conic-gradient(from 0deg,rgba(255,106,43,.7),transparent 28%)", animation: "sweep 4s linear infinite" }} />
      {blips.map((b) => (
        <div key={b.id} style={{ position: "absolute", left: `${b.x}%`, top: `${b.y}%`, width: 12, height: 12, marginLeft: -6, marginTop: -6 }}>
          <div style={{ position: "absolute", inset: 0, borderRadius: "50%", background: RED }} />
          <div style={{ position: "absolute", inset: 0, borderRadius: "50%", border: `2px solid ${RED}`, animation: "blip 1.6s ease-out infinite" }} />
        </div>
      ))}
    </div>
  );
}

export default function App() {
  const [stats, setStats] = useState({ total: 0, blocked: 0, safe: 0, rate: 0, agreed: 0, overrode: 0, ml_only: 0, fp_corrected: 0, fn_caught: 0 });
  const [recent, setRecent] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [health, setHealth] = useState(null);
  const [online, setOnline] = useState(true);
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [open, setOpen] = useState(null);
  const [pipe, setPipe] = useState(-1);
  const [blips, setBlips] = useState([]);
  const [now, setNow] = useState(new Date());
  const lastId = useRef(null);

  const refresh = useCallback(async () => {
    try {
      const [s, r] = await Promise.all([axios.get(`${API}/stats`), axios.get(`${API}/recent?limit=20`)]);
      setStats(s.data);
      setRecent(r.data);
      const newest = r.data.length ? r.data[0].id : 0;
      if (lastId.current === null || newest < lastId.current) lastId.current = newest;
      else if (newest > lastId.current) {
        const fresh = r.data.filter((e) => e.id > lastId.current && e.verdict === "MALICIOUS");
        if (fresh.length) setBlips((b) => [...b, ...fresh.map((e) => ({ id: e.id, ...place(e.url), t: Date.now() }))]);
        lastId.current = newest;
      }
      setOnline(true);
    } catch {
      setOnline(false);
    }
  }, []);

  useEffect(() => {
    axios.get(`${API}/metrics`).then((r) => setMetrics(r.data)).catch(() => {});
  }, []);
  useEffect(() => {
    refresh();
    const a = setInterval(refresh, 3000);
    return () => clearInterval(a);
  }, [refresh]);
  useEffect(() => {
    const h = () => axios.get(`${API}/health`).then((r) => setHealth(r.data)).catch(() => setHealth(null));
    h();
    const a = setInterval(h, 10000);
    return () => clearInterval(a);
  }, []);
  useEffect(() => {
    const a = setInterval(() => {
      setNow(new Date());
      setBlips((b) => {
        const f = b.filter((x) => Date.now() - x.t < 8000);
        return f.length === b.length ? b : f;
      });
    }, 1000);
    return () => clearInterval(a);
  }, []);

  async function handleScan() {
    const u = url.trim();
    if (!u || scanning) return;
    setScanning(true);
    setResult(null);
    setPipe(0);
    const timers = [1, 2, 3, 4].map((i) => setTimeout(() => setPipe((p) => Math.max(p, i)), i * 350));
    try {
      const r = await axios.post(`${API}/classify`, { url: u });
      timers.forEach(clearTimeout);
      setResult(r.data);
      setPipe(5);
      setTimeout(() => setPipe(-1), 2500);
      refresh();
    } catch {
      timers.forEach(clearTimeout);
      setPipe(-1);
      setResult({ verdict: "ERROR", confidence: 0, reasons: ["API not reachable. Start the backend with: python main.py"] });
    }
    setScanning(false);
  }

  const acc = metrics ? (metrics.accuracy * 100).toFixed(2) : health ? (health.accuracy * 100).toFixed(2) : "--";
  const cm = metrics && metrics.confusion_matrix;
  const bars = metrics ? [
    { n: "Random Forest", v: metrics.rf_accuracy_calibrated, c: ORANGE },
    { n: "XGBoost", v: metrics.xgb_accuracy_calibrated, c: ORANGE },
    { n: "Ensemble", v: metrics.accuracy, c: VIOLET },
  ] : [];
  let s = 0, m = 0;
  const timeline = [...recent].reverse().map((e, i) => {
    if (e.verdict === "MALICIOUS") m++; else s++;
    return { n: i + 1, safe: s, malicious: m };
  });
  const roc = metrics && metrics.roc ? metrics.roc.fpr.map((f, i) => ({ fpr: f, tpr: metrics.roc.tpr[i], ref: f })) : [];
  const top5 = metrics && metrics.rf_feature_importance ? metrics.rf_feature_importance.slice(0, 5) : [];
  const topMax = top5.length ? top5[0].importance : 1;
  const alertColor = result && result.verdict === "SAFE" ? GREEN : RED;
  const tip = { background: "#1a0e0a", border: "1px solid rgba(255,255,255,.2)", borderRadius: 8, fontSize: 13, color: "#fff" };

  return (
    <div style={{ minHeight: "100vh", background: "#140503", color: "#fff", fontFamily: "Inter,'Segoe UI',Arial,sans-serif", fontSize: 15, position: "relative", overflow: "hidden" }}>
      <style>{css}</style>
      <div className="bg">
        <div style={{ left: -60, top: -120, width: "120%", height: 260, borderRadius: 0, transform: "rotate(14deg)", filter: "blur(60px)", opacity: 0.9, animation: "drift 14s ease-in-out infinite",
          background: "linear-gradient(100deg,transparent 20%,#ff5a1f 42%,#ffa05a 50%,#ff5a1f 58%,transparent 80%)" }} />
        <div style={{ left: -160, bottom: -200, width: 720, height: 560, background: "#ff4d17", filter: "blur(120px)", opacity: 0.85, animation: "drift 18s ease-in-out infinite" }} />
        <div style={{ right: -140, bottom: -160, width: 620, height: 520, background: "#c92d0a", filter: "blur(120px)", opacity: 0.9, animation: "drift 16s 3s ease-in-out infinite" }} />
      </div>

      <div className="panel">
        {/* HEADER */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          <div>
            <div style={{ fontSize: 32, fontWeight: 800, letterSpacing: ".03em" }}>CYBER<span style={{ color: ORANGE }}>SHIELD</span></div>
            <div className="sub" style={{ letterSpacing: ".16em", marginTop: 2 }}>AI BASED CYBER THREAT DETECTION SYSTEM</div>
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <div className="pill" style={{ padding: "8px 16px", fontSize: 13, background: online ? "rgba(95,240,160,.14)" : "rgba(255,90,90,.2)", color: online ? GREEN : "#ff8a80" }}>
              <span style={{ animation: "pulse 2s infinite", display: "inline-block" }}>●</span> {online ? `ACTIVE · ${acc}% ACC` : "API OFFLINE"}
            </div>
            <div className="pill" style={{ padding: "8px 16px", fontSize: 14, background: "rgba(255,255,255,.08)", fontFamily: "Consolas,monospace" }}>{now.toLocaleTimeString()}</div>
          </div>
        </div>

        {/* STAT CARDS */}
        <div className="g4">
          {[
            { l: "Total scans", v: stats.total.toLocaleString(), c: "#fff", t: "LIVE", tb: "rgba(255,255,255,.1)", tc: "#fff" },
            { l: "Threats blocked", v: stats.blocked.toLocaleString(), c: RED, t: "BLOCKED", tb: "rgba(255,90,90,.2)", tc: "#ff8a80" },
            { l: "Threat rate", v: `${stats.rate}%`, c: AMBER, t: "RATE", tb: "rgba(255,176,46,.18)", tc: "#ffc766" },
            { l: "Model accuracy", v: `${acc}%`, c: GREEN, t: "ENSEMBLE", tb: "rgba(95,240,160,.15)", tc: GREEN },
          ].map((c, i) => (
            <div key={i} className="card" style={{ padding: "14px 20px" }}>
              <div className="sub">{c.l}</div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 36, fontWeight: 800, color: c.c }}>{c.v}</span>
                <span className="pill" style={{ background: c.tb, color: c.tc }}>{c.t}</span>
              </div>
            </div>
          ))}
        </div>

        {/* SCANNER */}
        <div className="card" style={{ padding: 12 }}>
          <div style={{ display: "flex", gap: 12 }}>
            <input value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleScan()}
              placeholder="Enter a URL to scan, e.g. paypal-secure-login-verify.tk"
              style={{ flex: 1, height: 48, background: "rgba(0,0,0,.55)", border: "1px solid rgba(255,255,255,.16)", borderRadius: 14, padding: "0 18px", color: "#fff", fontSize: 16, fontFamily: "Consolas,monospace" }} />
            <button onClick={handleScan} style={{ height: 48, minWidth: 130, padding: "0 30px", background: "#0a0a0c", border: "1px solid rgba(255,255,255,.3)", borderRadius: 14, color: "#fff", fontSize: 15, fontWeight: 700, letterSpacing: ".12em" }}>
              {scanning ? "SCANNING..." : "SCAN"}
            </button>
          </div>
          {result && (
            <div style={{ marginTop: 12, padding: "14px 18px", borderRadius: 14, animation: "fade .3s ease",
              background: result.verdict === "SAFE" ? "rgba(95,240,160,.07)" : "rgba(255,90,90,.08)",
              border: `1px solid ${result.verdict === "SAFE" ? "rgba(95,240,160,.35)" : "rgba(255,90,90,.35)"}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                <span style={{ fontSize: 24, fontWeight: 800, color: alertColor }}>{result.verdict === "SAFE" ? "SAFE" : result.verdict}</span>
                <span className="sub" style={{ fontSize: 15 }}>Confidence <b style={{ color: alertColor }}>{result.confidence}%</b></span>
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {(result.reasons || []).map((r, i) => <span key={i} className="chip">{r}</span>)}
              </div>
              {result.ai_verdict && (
                <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid rgba(255,255,255,.12)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <span className="lbl" style={{ color: "#ffb48a", letterSpacing: ".08em", fontSize: 14 }}>GEMINI ANALYSIS: {result.ai_verdict} ({result.ai_confidence}%)</span>
                    {result.agreement === false && <span className="pill" style={{ background: "rgba(255,176,46,.16)", color: AMBER }}>AI OVERRODE ML</span>}
                  </div>
                  <div style={{ fontSize: 15, lineHeight: 1.5 }}>{result.ai_reason}</div>
                  {result.ml_verdict && <div className="sub" style={{ marginTop: 6 }}>ML model alone said: <b style={{ color: result.ml_verdict === "SAFE" ? GREEN : RED }}>{result.ml_verdict}</b> ({result.ml_confidence}%)</div>}
                </div>
              )}
            </div>
          )}
        </div>

        {/* RADAR + LOG */}
        <div className="gA">
          <div className="card">
            <div className="lbl">Threat radar</div>
            <div className="sub">Blips appear on real malicious scans</div>
            <Radar blips={blips} />
            <div className="sub" style={{ textAlign: "center" }}>{blips.length ? `${blips.length} new threat${blips.length > 1 ? "s" : ""}` : "Monitoring..."}</div>
          </div>
          <div className="card">
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span className="lbl">Live scan log</span><span className="sub">Safe and malicious only. Click a row for details</span>
            </div>
            <div style={{ marginTop: 8 }}>
              {recent.length === 0 && <div className="sub" style={{ padding: "18px 0" }}>No scans yet. Scan a URL or hover a link with the extension.</div>}
              {recent.slice(0, 8).map((e) => (
                <div key={e.id}>
                  <div className="row" onClick={() => setOpen(open === e.id ? null : e.id)}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.url}</span>
                    <span className="pill" style={pillStyle(e.verdict)}>{e.verdict}</span>
                    <div className="bar"><div style={{ width: `${e.confidence}%`, height: "100%", background: e.verdict === "SAFE" ? GREEN : RED }} /></div>
                    <span className="sub">{new Date(e.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
                  </div>
                  {open === e.id && (
                    <div style={{ padding: "8px 4px 12px", animation: "fade .2s ease" }}>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>{(e.reasons || []).map((r, i) => <span key={i} className="chip">{r}</span>)}</div>
                      {e.ai_reason && <div className="sub">Gemini: {e.ai_reason}</div>}
                      {e.ml_verdict && <div className="sub">ML alone: {e.ml_verdict} ({e.ml_confidence}%)</div>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* PERFORMANCE + GAUGE + ROC */}
        <div className="gB">
          <div className="card">
            <div className="lbl">Model performance</div>
            <div className="sub">Test accuracy, bars scaled 90 to 100%</div>
            {metrics ? (
              <>
                <div style={{ display: "flex", gap: 22, justifyContent: "center", alignItems: "flex-end", margin: "12px 0" }}>
                  {bars.map((b) => (
                    <div key={b.n} style={{ textAlign: "center" }}>
                      <div style={{ width: 46, height: 100, borderRadius: 12, background: "rgba(255,255,255,.08)", display: "flex", alignItems: "flex-end" }}>
                        <div style={{ width: "100%", height: `${Math.min(100, Math.max(4, (b.v * 100 - 90) * 10))}%`, borderRadius: 12, background: b.c, transition: "height 1s ease" }} />
                      </div>
                      <div style={{ fontWeight: 700, marginTop: 4 }}>{(b.v * 100).toFixed(2)}%</div>
                      <div className="sub">{b.n}</div>
                    </div>
                  ))}
                </div>
                {cm && (
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    {[["True positive", cm.tp, GREEN], ["True negative", cm.tn, BLUE], ["False positive", cm.fp, AMBER], ["False negative", cm.fn, RED]].map(([l, v, c]) => (
                      <div key={l} style={{ padding: "8px 12px", borderRadius: 12, background: "rgba(0,0,0,.35)", border: `1px solid ${c}33` }}>
                        <div style={{ fontSize: 20, fontWeight: 800, color: c, fontFamily: "Consolas,monospace" }}>{v.toLocaleString()}</div>
                        <div style={{ fontSize: 12, color: c }}>{l}</div>
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : <div className="sub" style={{ padding: "20px 0" }}>Waiting for metrics from the backend...</div>}
          </div>

          <div className="card">
            <div className="lbl">Threat distribution</div>
            <Gauge pct={stats.rate} />
            <div style={{ display: "flex", justifyContent: "center", gap: 28, marginTop: 6 }}>
              <span><b style={{ color: GREEN, fontSize: 20 }}>{stats.safe}</b> <span className="sub">safe</span></span>
              <span><b style={{ color: RED, fontSize: 20 }}>{stats.blocked}</b> <span className="sub">malicious</span></span>
            </div>
          </div>

          <div className="card glow">
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span className="lbl">ROC curve</span>
              <span style={{ fontFamily: "Consolas,monospace", color: GREEN, fontWeight: 700 }}>AUC {metrics ? metrics.auc_roc.toFixed(4) : "--"}</span>
            </div>
            <div style={{ height: 230, marginTop: 8 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={roc}>
                  <XAxis dataKey="fpr" type="number" domain={[0, 1]} tick={{ fill: "#cfcfd6", fontSize: 12 }} axisLine={false} tickLine={false} tickFormatter={(v) => v.toFixed(1)} />
                  <YAxis domain={[0, 1]} tick={{ fill: "#cfcfd6", fontSize: 12 }} axisLine={false} tickLine={false} tickFormatter={(v) => v.toFixed(1)} />
                  <Tooltip contentStyle={tip} formatter={(v) => v.toFixed(3)} />
                  <Line type="monotone" dataKey="ref" stroke="rgba(255,255,255,.35)" strokeDasharray="5 5" dot={false} />
                  <Line type="monotone" dataKey="tpr" stroke="#ffd0b0" strokeWidth={3} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* TIMELINE + AGREEMENT + TOP 5 */}
        <div className="gC">
          <div className="card">
            <div className="lbl">Scan timeline</div>
            <div className="sub">Last 20 scans, running totals</div>
            <div style={{ height: 190, marginTop: 8 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline}>
                  <defs>
                    <linearGradient id="gs" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={GREEN} stopOpacity={0.4} /><stop offset="1" stopColor={GREEN} stopOpacity={0} /></linearGradient>
                    <linearGradient id="gm" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={RED} stopOpacity={0.4} /><stop offset="1" stopColor={RED} stopOpacity={0} /></linearGradient>
                  </defs>
                  <XAxis dataKey="n" tick={{ fill: "#cfcfd6", fontSize: 12 }} axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fill: "#cfcfd6", fontSize: 12 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tip} />
                  <Area type="monotone" dataKey="safe" stroke={GREEN} fill="url(#gs)" strokeWidth={3} name="Safe" />
                  <Area type="monotone" dataKey="malicious" stroke={RED} fill="url(#gm)" strokeWidth={3} name="Malicious" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="card">
            <div className="lbl">ML vs Gemini agreement</div>
            <div className="sub">Last 500 scans</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, margin: "14px 0" }}>
              {[["Agreed", stats.agreed, GREEN], ["AI overrode ML", stats.overrode, AMBER], ["No AI (whitelist)", stats.ml_only, "#cfcfd6"]].map(([l, v, c]) => (
                <div key={l} style={{ textAlign: "center", padding: "10px 4px", borderRadius: 14, background: "rgba(0,0,0,.35)" }}>
                  <div style={{ fontSize: 28, fontWeight: 800, color: c }}>{v}</div>
                  <div style={{ fontSize: 12, color: "#cfcfd6" }}>{l}</div>
                </div>
              ))}
            </div>
            <div style={{ fontSize: 15, lineHeight: 1.9 }}>
              <div><b style={{ color: AMBER }}>{stats.fp_corrected}</b> <span className="sub" style={{ fontSize: 14 }}>ML false positives corrected by AI</span></div>
              <div><b style={{ color: RED }}>{stats.fn_caught}</b> <span className="sub" style={{ fontSize: 14 }}>threats caught by AI that ML missed</span></div>
            </div>
          </div>

          <div className="card">
            <div className="lbl">Top features (Random Forest)</div>
            <div className="sub">What the model relies on most</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 11, marginTop: 14 }}>
              {top5.length === 0 && <div className="sub">Waiting for metrics...</div>}
              {top5.map((f, i) => (
                <div key={f.feature} style={{ display: "grid", gridTemplateColumns: "130px 1fr 52px", gap: 10, alignItems: "center" }}>
                  <span style={{ fontFamily: "Consolas,monospace", fontSize: 13 }}>{f.feature}</span>
                  <div className="bar"><div style={{ width: `${(f.importance / topMax) * 100}%`, height: "100%", background: i === 0 ? ORANGE : "#ff9a66" }} /></div>
                  <span style={{ textAlign: "right", fontWeight: 700 }}>{(f.importance * 100).toFixed(1)}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* PIPELINE */}
        <div className="card">
          <div className="lbl" style={{ marginBottom: 14 }}>Detection pipeline</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(6,1fr)", gap: 10 }}>
            {PIPES.map((p, i) => {
              const active = pipe === i, done = pipe > i, last = i === 5 && pipe === 5;
              const col = last ? alertColor : active ? ORANGE : done ? GREEN : "rgba(255,255,255,.18)";
              return (
                <div key={p} style={{ textAlign: "center", padding: "14px 6px", borderRadius: 16, transition: "all .3s",
                  background: active || last ? `${col}22` : "rgba(0,0,0,.25)", border: `1px solid ${col}`,
                  boxShadow: active || last ? `0 0 22px ${col}55` : "none" }}>
                  <div style={{ width: 32, height: 32, margin: "0 auto 8px", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, border: `2px solid ${col}`, color: pipe >= i ? col : "#cfcfd6" }}>{i + 1}</div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: pipe >= i ? "#fff" : "#cfcfd6" }}>{p}</div>
                </div>
              );
            })}
          </div>
          <div className="sub" style={{ marginTop: 10 }}>Lights up step by step while a URL is being scanned</div>
        </div>
      </div>
    </div>
  );
}
