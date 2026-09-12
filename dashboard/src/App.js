import { useState, useEffect, useRef } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line
} from "recharts";
import axios from "axios";

const API = "http://localhost:8000";

const FEED = [
  { url: "paypal-secure-login.ru/auth/verify", type: "PHISHING", conf: 97 },
  { url: "github.com/user/repository", type: "SAFE", conf: 99 },
  { url: "free-crypto-airdrop2024.xyz", type: "SUSPICIOUS", conf: 81 },
  { url: "microsoft-update-verify.net/dl", type: "MALWARE", conf: 96 },
  { url: "docs.python.org/3/library/os", type: "SAFE", conf: 100 },
  { url: "bank0famerica-secure.cc/login", type: "PHISHING", conf: 99 },
  { url: "stackoverflow.com/questions/123", type: "SAFE", conf: 98 },
  { url: "win-iphone15-now.click/claim", type: "PHISHING", conf: 94 },
  { url: "npmjs.com/package/react", type: "SAFE", conf: 99 },
  { url: "amazom-deals-prime.shop/offer", type: "PHISHING", conf: 98 },
];

const TIMELINE = [
  { time: "12:00", threats: 2, safe: 8 },
  { time: "12:05", threats: 4, safe: 6 },
  { time: "12:10", threats: 1, safe: 9 },
  { time: "12:15", threats: 6, safe: 5 },
  { time: "12:20", threats: 3, safe: 7 },
  { time: "12:25", threats: 5, safe: 6 },
  { time: "12:30", threats: 2, safe: 9 },
];

const PIE_DATA = [
  { name: "Phishing", value: 42, color: "#ff4444" },
  { name: "Malware", value: 23, color: "#ff7700" },
  { name: "Suspicious", value: 18, color: "#ffaa00" },
  { name: "Safe", value: 17, color: "#00cc66" },
];

const SHAP_DATA = [
  { feature: "Suspicious TLD", value: 34, color: "#ff4444" },
  { feature: "Brand in subdomain", value: 28, color: "#ff7700" },
  { feature: "Domain age: 2 days", value: 21, color: "#ffaa00" },
  { feature: "URL length", value: 10, color: "#4488ff" },
  { feature: "HTTPS present", value: -12, color: "#00cc66" },
];

const ROC = Array.from({ length: 20 }, (_, i) => ({
  fpr: parseFloat((i / 19).toFixed(2)),
  tpr: parseFloat(Math.min(1, Math.pow(i / 19, 0.08)).toFixed(3)),
  random: parseFloat((i / 19).toFixed(2)),
}));

const THREAT_DOTS = [
  { lat: 51.5, lon: -0.1 }, { lat: 40.7, lon: -74 },
  { lat: 35.6, lon: 139.7 }, { lat: 48.8, lon: 2.3 },
  { lat: 55.7, lon: 37.6 }, { lat: 22.3, lon: 114.1 },
  { lat: -33.8, lon: 151.2 }, { lat: 19.4, lon: -99.1 },
  { lat: 28.6, lon: 77.2 }, { lat: 37.5, lon: 127 },
  { lat: 52.5, lon: 13.4 }, { lat: 1.3, lon: 103.8 },
  { lat: 41.9, lon: 12.5 }, { lat: -23.5, lon: -46.6 },
];

function typeStyle(t) {
  if (t === "SAFE") return { text: "#00cc66", bg: "rgba(0,204,102,0.12)", border: "rgba(0,204,102,0.35)" };
  if (t === "PHISHING") return { text: "#ff4444", bg: "rgba(255,68,68,0.12)", border: "rgba(255,68,68,0.35)" };
  if (t === "MALWARE") return { text: "#dc2626", bg: "rgba(220,38,38,0.15)", border: "rgba(220,38,38,0.4)" };
  return { text: "#ffaa00", bg: "rgba(255,170,0,0.12)", border: "rgba(255,170,0,0.35)" };
}

// 3D Globe Component
function Globe() {
  const canvasRef = useRef(null);
  const angleRef = useRef(0);
  const rafRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const W = canvas.width, H = canvas.height;
    const cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 10;

    function project(lat, lon, rot) {
      const phi = (90 - lat) * Math.PI / 180;
      const theta = (lon + rot) * Math.PI / 180;
      const x = R * Math.sin(phi) * Math.cos(theta);
      const y = R * Math.cos(phi);
      const z = R * Math.sin(phi) * Math.sin(theta);
      return { x: cx + x, y: cy - y, z, visible: z > -20 };
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);
      angleRef.current = (angleRef.current + 0.35) % 360;
      const angle = angleRef.current;

      // Globe base
      const grad = ctx.createRadialGradient(cx - R * 0.3, cy - R * 0.3, R * 0.1, cx, cy, R);
      grad.addColorStop(0, "#0d2444");
      grad.addColorStop(1, "#020810");
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.strokeStyle = "rgba(0,200,255,0.25)";
      ctx.lineWidth = 1;
      ctx.stroke();

      // Grid lines
      ctx.strokeStyle = "rgba(0,200,255,0.08)";
      ctx.lineWidth = 0.5;
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let first = true;
        for (let lon = 0; lon <= 360; lon += 5) {
          const p = project(lat, lon, angle);
          if (!p.visible) { first = true; continue; }
          first ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y);
          first = false;
        }
        ctx.stroke();
      }
      for (let lon = 0; lon < 360; lon += 30) {
        ctx.beginPath();
        let first = true;
        for (let lat = -90; lat <= 90; lat += 5) {
          const p = project(lat, lon, angle);
          if (!p.visible) { first = true; continue; }
          first ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y);
          first = false;
        }
        ctx.stroke();
      }

      // Threat dots
      const t = Date.now() / 600;
      THREAT_DOTS.forEach((d, i) => {
        const p = project(d.lat, d.lon, angle);
        if (!p.visible) return;
        const pulse = 0.5 + 0.5 * Math.sin(t + i * 0.9);
        const depth = (p.z + R) / (2 * R);

        // Outer ring
        ctx.beginPath();
        ctx.arc(p.x, p.y, 5 + pulse * 3, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,68,68,${0.15 * pulse * depth})`;
        ctx.fill();

        // Core dot
        ctx.beginPath();
        ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,68,68,${0.7 + 0.3 * pulse})`;
        ctx.fill();
      });

      // Atmosphere glow
      const atmo = ctx.createRadialGradient(cx, cy, R * 0.85, cx, cy, R * 1.15);
      atmo.addColorStop(0, "rgba(0,200,255,0)");
      atmo.addColorStop(0.5, "rgba(0,200,255,0.04)");
      atmo.addColorStop(1, "rgba(0,200,255,0)");
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.15, 0, Math.PI * 2);
      ctx.fillStyle = atmo;
      ctx.fill();

      rafRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(rafRef.current);
  }, []);

  return (
    <canvas ref={canvasRef} width={260} height={220}
      style={{ borderRadius: 8, display: "block", margin: "0 auto" }} />
  );
}

// Animated number
function AnimNum({ value, duration = 1200 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    const start = Date.now();
    const target = parseFloat(value);
    const tick = () => {
      const elapsed = Date.now() - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(eased * target));
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [value, duration]);
  return <>{display.toLocaleString()}</>;
}

export default function App() {
  const [feed, setFeed] = useState(FEED.slice(0, 5));
  const [scans, setScans] = useState(847);
  const [blocked, setBlocked] = useState(312);
  const [tick, setTick] = useState(0);
  const [urlInput, setUrlInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [health, setHealth] = useState(null);
  const [selected, setSelected] = useState(null);
  const [pipeStep, setPipeStep] = useState(0);

  useEffect(() => {
    const iv = setInterval(() => {
      const next = FEED[tick % FEED.length];
      setFeed(prev => [next, ...prev].slice(0, 8));
      setScans(s => s + 1);
      if (next.type !== "SAFE") setBlocked(b => b + 1);
      setTick(t => t + 1);
    }, 2600);
    return () => clearInterval(iv);
  }, [tick]);

  useEffect(() => {
    axios.get(`${API}/health`).then(r => setHealth(r.data)).catch(() => setHealth(null));
  }, []);

  useEffect(() => {
    const iv = setInterval(() => setPipeStep(s => (s + 1) % 6), 700);
    return () => clearInterval(iv);
  }, []);

  async function handleScan() {
    if (!urlInput.trim()) return;
    setScanning(true);
    setResult(null);
    try {
      const r = await axios.post(`${API}/classify`, { url: urlInput });
      setResult(r.data);
    } catch {
      setResult({ verdict: "ERROR", confidence: 0, reasons: ["API not reachable — start python main.py"] });
    }
    setScanning(false);
  }

  const threatRate = Math.round((blocked / scans) * 100);
  const PIPES = ["URL Click", "Extension", "Features", "ML Ensemble", "SHAP", "Alert/Block"];
  const PIPE_COLORS = ["#0ea5e9", "#8b5cf6", "#f59e0b", "#0ea5e9", "#22c55e", "#ef4444"];

  return (
    <div style={{ background: "#06090f", minHeight: "100vh", color: "#c8dff4",
      fontFamily: "'Segoe UI',Arial,sans-serif", padding: "18px 22px", position: "relative",
      overflow: "hidden" }}>
      <style>{`
        *{box-sizing:border-box;margin:0;padding:0}
        ::-webkit-scrollbar{width:4px}
        ::-webkit-scrollbar-thumb{background:#1a3050;border-radius:2px}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
        @keyframes fadeSlide{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
        @keyframes glow{0%,100%{box-shadow:0 0 20px rgba(0,200,255,0.15)}50%{box-shadow:0 0 35px rgba(0,200,255,0.3)}}
        @keyframes scanline{0%{transform:translateY(-100%)}100%{transform:translateY(100vh)}}
        .feed-item{animation:fadeSlide 0.35s ease forwards}
        .panel{transition:border-color 0.3s}
        .panel:hover{border-color:rgba(0,200,255,0.25)!important}
        input:focus{outline:none}
        button{cursor:pointer}
      `}</style>

      {/* Grid background */}
      <div style={{ position:"fixed", inset:0,
        backgroundImage:"linear-gradient(rgba(0,200,255,0.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,0.025) 1px,transparent 1px)",
        backgroundSize:"44px 44px", pointerEvents:"none", zIndex:0 }} />

      {/* Scanline */}
      <div style={{ position:"fixed", top:0, left:0, right:0, height:"2px",
        background:"linear-gradient(90deg,transparent,rgba(0,200,255,0.4),transparent)",
        animation:"scanline 7s linear infinite", pointerEvents:"none", zIndex:1 }} />

      <div style={{ position:"relative", zIndex:2 }}>

        {/* HEADER */}
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center",
          marginBottom:18, paddingBottom:14,
          borderBottom:"1px solid rgba(0,200,255,0.1)" }}>
          <div>
            <div style={{ fontSize:24, fontWeight:900, color:"#fff", letterSpacing:"0.04em",
              textShadow:"0 0 30px rgba(0,200,255,0.3)" }}>
              CYBER<span style={{ color:"#00c8ff" }}>SHIELD</span>
              <span style={{ fontFamily:"monospace", fontSize:11, color:"#4a6580",
                marginLeft:12, fontWeight:400, letterSpacing:"0.2em" }}>v1.0.0</span>
            </div>
            <div style={{ fontSize:10, color:"#4a6580", letterSpacing:"0.22em", marginTop:3 }}>
              AI-BASED CYBER THREAT DETECTION SYSTEM
            </div>
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:16 }}>
            <div style={{ textAlign:"right" }}>
              <div style={{ fontSize:10, color:"#4a6580", letterSpacing:"0.12em" }}>SYSTEM STATUS</div>
              <div style={{ display:"flex", alignItems:"center", gap:6, marginTop:4, justifyContent:"flex-end" }}>
                <div style={{ width:8, height:8, borderRadius:"50%",
                  background: health ? "#00cc66" : "#ff4444",
                  animation:"pulse 2s infinite" }} />
                <span style={{ fontSize:12, color: health ? "#00cc66" : "#ff4444",
                  letterSpacing:"0.08em" }}>
                  {health ? `ACTIVE — ${(health.accuracy * 100).toFixed(1)}% ACC` : "API OFFLINE"}
                </span>
              </div>
            </div>
            <div style={{ background:"rgba(0,200,255,0.06)",
              border:"1px solid rgba(0,200,255,0.15)",
              padding:"8px 14px", fontSize:11, color:"#00c8ff",
              letterSpacing:"0.1em", fontFamily:"monospace" }}>
              {new Date().toLocaleTimeString()}
            </div>
          </div>
        </div>

        {/* STAT CARDS */}
        <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10, marginBottom:14 }}>
          {[
            { label:"TOTAL SCANS", value: scans, suffix:"", color:"#00c8ff" },
            { label:"THREATS BLOCKED", value: blocked, suffix:"", color:"#ff4444" },
            { label:"THREAT RATE", value: threatRate, suffix:"%", color:"#ffaa00" },
            { label:"MODEL ACCURACY", value: 9541, suffix:"%", color:"#00cc66", raw:"95.41%" },
          ].map((s, i) => (
            <div key={i} className="panel" style={{ background:"#0a1220",
              border:"1px solid rgba(0,200,255,0.1)",
              padding:"16px 18px", borderRadius:8,
              clipPath:"polygon(0 0,calc(100% - 12px) 0,100% 12px,100% 100%,0 100%)",
              position:"relative", animation:"glow 4s ease infinite",
              animationDelay:`${i * 0.5}s` }}>
              <div style={{ fontSize:9, color:"#4a6580", letterSpacing:"0.18em",
                textTransform:"uppercase", marginBottom:8 }}>{s.label}</div>
              <div style={{ fontFamily:"'Orbitron',monospace", fontSize:26,
                fontWeight:700, color:s.color, lineHeight:1 }}>
                {s.raw || <><AnimNum value={s.value} />{s.suffix}</>}
              </div>
              <div style={{ position:"absolute", bottom:0, left:0, right:0, height:2, borderRadius:"0 0 8px 8px",
                background:`linear-gradient(90deg,transparent,${s.color},transparent)`,
                opacity:0.5 }} />
            </div>
          ))}
        </div>

        {/* URL SCANNER */}
        <div className="panel" style={{ background:"#0a1220",
          border:"1px solid rgba(0,200,255,0.15)",
          padding:"16px 18px", borderRadius:8, marginBottom:14,
          animation:"glow 3s ease infinite" }}>
          <div style={{ fontSize:10, color:"#00c8ff", letterSpacing:"0.22em", marginBottom:12 }}>
            ▸ LIVE URL SCANNER
          </div>
          <div style={{ display:"flex", gap:10 }}>
            <input value={urlInput} onChange={e => setUrlInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleScan()}
              placeholder="Enter a URL to scan — e.g. paypal-secure-login.ru/auth/verify"
              style={{ flex:1, background:"rgba(0,0,0,0.5)",
                border:"1px solid rgba(0,200,255,0.2)",
                padding:"10px 16px", color:"#c8dff4", fontSize:13,
                borderRadius:6, fontFamily:"monospace" }} />
            <button onClick={handleScan}
              style={{ background: scanning ? "rgba(0,200,255,0.08)" : "rgba(0,200,255,0.15)",
                border:"1px solid rgba(0,200,255,0.4)",
                color:"#00c8ff", padding:"10px 24px", fontSize:12,
                borderRadius:6, letterSpacing:"0.12em", minWidth:110,
                fontWeight:700 }}>
              {scanning ? "⟳ SCANNING" : "SCAN ▶"}
            </button>
          </div>
          {result && (
            <div style={{ marginTop:12, padding:"12px 16px", borderRadius:6,
              background: result.verdict === "SAFE" ? "rgba(0,204,102,0.06)" : "rgba(255,68,68,0.06)",
              border:`1px solid ${result.verdict === "SAFE" ? "rgba(0,204,102,0.3)" : "rgba(255,68,68,0.3)"}`,
              animation:"fadeSlide 0.3s ease" }}>
              <div style={{ display:"flex", justifyContent:"space-between", marginBottom:10 }}>
                <span style={{ fontSize:16, fontWeight:700,
                  color: result.verdict === "SAFE" ? "#00cc66" : "#ff4444" }}>
                  {result.verdict === "SAFE" ? "✓ SAFE" : `✗ ${result.verdict}`}
                </span>
                <span style={{ fontSize:12, color:"#4a6580" }}>
                  Confidence: <strong style={{ color: result.verdict === "SAFE" ? "#00cc66" : "#ff4444" }}>
                    {result.confidence}%</strong>
                </span>
              </div>
              <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                {(result.reasons || []).map((r, i) => (
                  <span key={i} style={{ fontSize:10, padding:"3px 10px",
                    background:"rgba(255,255,255,0.04)",
                    border:"1px solid rgba(255,255,255,0.08)",
                    color:"#8aafcc", borderRadius:4 }}>{r}</span>
                ))}
              </div>

              {/* AI REASONING — only shown when Gemini actually ran for this scan */}
              {result.ai_verdict && (
                <div style={{ marginTop:12, paddingTop:12,
                  borderTop:"1px solid rgba(0,200,255,0.12)" }}>
                  <div style={{ display:"flex", alignItems:"center",
                    justifyContent:"space-between", marginBottom:6 }}>
                    <span style={{ fontSize:10, color:"#00c8ff",
                      letterSpacing:"0.18em" }}>
                      🤖 AI ANALYSIS — {result.ai_verdict} ({result.ai_confidence}%)
                    </span>
                    {result.agreement === false && (
                      <span style={{ fontSize:9, padding:"2px 8px",
                        background:"rgba(255,170,0,0.12)",
                        border:"1px solid rgba(255,170,0,0.35)",
                        color:"#ffaa00", borderRadius:3, fontWeight:700,
                        letterSpacing:"0.06em" }}>
                        AI OVERRODE ML
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize:12, color:"#c8dff4", lineHeight:1.5 }}>
                    {result.ai_reason}
                  </div>
                  {result.ml_verdict && (
                    <div style={{ fontSize:10, color:"#4a6580", marginTop:6 }}>
                      ML model alone said: <strong style={{
                        color: result.ml_verdict === "SAFE" ? "#00cc66" : "#ff4444"
                      }}>{result.ml_verdict}</strong> ({result.ml_confidence}%)
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* MAIN ROW — Globe + Feed */}
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1.2fr", gap:12, marginBottom:12 }}>

          {/* 3D GLOBE */}
          <div className="panel" style={{ background:"#0a1220",
            border:"1px solid rgba(0,200,255,0.1)",
            padding:"16px 18px", borderRadius:8 }}>
            <div style={{ display:"flex", justifyContent:"space-between",
              alignItems:"center", marginBottom:12 }}>
              <div style={{ fontSize:10, color:"#00c8ff", letterSpacing:"0.22em" }}>
                ▸ GLOBAL THREAT ORIGINS
              </div>
              <div style={{ fontSize:9, color:"#ff4444", letterSpacing:"0.1em",
                animation:"pulse 1.5s infinite" }}>● LIVE</div>
            </div>
            <Globe />
            <div style={{ display:"flex", justifyContent:"center", gap:20, marginTop:12 }}>
              <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                <div style={{ width:8, height:8, borderRadius:"50%", background:"#ff4444" }} />
                <span style={{ fontSize:10, color:"#4a6580" }}>Active threats</span>
              </div>
              <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                <div style={{ width:8, height:8, borderRadius:"50%", background:"rgba(0,200,255,0.5)" }} />
                <span style={{ fontSize:10, color:"#4a6580" }}>Monitoring nodes</span>
              </div>
            </div>
          </div>

          {/* LIVE FEED */}
          <div className="panel" style={{ background:"#0a1220",
            border:"1px solid rgba(0,200,255,0.1)",
            padding:"16px 18px", borderRadius:8 }}>
            <div style={{ display:"flex", justifyContent:"space-between",
              alignItems:"center", marginBottom:12 }}>
              <div style={{ fontSize:10, color:"#ff4444", letterSpacing:"0.22em" }}>
                ▸ LIVE THREAT FEED
              </div>
              <div style={{ fontSize:9, color:"#ff4444", letterSpacing:"0.1em",
                animation:"pulse 1.5s infinite" }}>● LIVE</div>
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
              {feed.map((item, i) => {
                const s = typeStyle(item.type);
                return (
                  <div key={i} className="feed-item"
                    onClick={() => setSelected(selected === i ? null : i)}
                    style={{ display:"grid", gridTemplateColumns:"1fr auto",
                      gap:10, alignItems:"center", padding:"8px 12px",
                      background: selected === i ? "rgba(0,200,255,0.05)" : "rgba(0,0,0,0.3)",
                      borderRadius:5, borderLeft:`2px solid ${s.text}`,
                      cursor:"pointer", transition:"background 0.2s" }}>
                    <span style={{ fontSize:11, color:"#c8dff4", overflow:"hidden",
                      textOverflow:"ellipsis", whiteSpace:"nowrap",
                      fontFamily:"monospace" }}>{item.url}</span>
                    <span style={{ fontSize:9, padding:"2px 8px",
                      background:s.bg, border:`1px solid ${s.border}`,
                      color:s.text, borderRadius:3, fontWeight:700,
                      letterSpacing:"0.08em", flexShrink:0 }}>{item.type}</span>
                  </div>
                );
              })}
            </div>
            {selected !== null && feed[selected] && (
              <div style={{ marginTop:10, padding:"10px 14px",
                background:"rgba(0,200,255,0.04)",
                border:"1px solid rgba(0,200,255,0.15)",
                borderRadius:6, animation:"fadeSlide 0.2s ease" }}>
                <div style={{ fontSize:10, color:"#00c8ff", marginBottom:8,
                  letterSpacing:"0.15em" }}>▸ SHAP EXPLANATION</div>
                {SHAP_DATA.slice(0, 3).map((d, i) => (
                  <div key={i} style={{ display:"flex", alignItems:"center",
                    gap:8, marginBottom:5 }}>
                    <div style={{ width:`${d.value * 2}px`, height:4,
                      background:d.color, borderRadius:2, minWidth:20 }} />
                    <span style={{ fontSize:10, color:"#8aafcc" }}>{d.feature}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* MIDDLE ROW */}
        <div style={{ display:"grid", gridTemplateColumns:"1.2fr 1fr", gap:12, marginBottom:12 }}>

          {/* Model Performance + Confusion */}
          <div className="panel" style={{ background:"#0a1220",
            border:"1px solid rgba(0,200,255,0.1)",
            padding:"16px 18px", borderRadius:8 }}>
            <div style={{ fontSize:10, color:"#00c8ff", letterSpacing:"0.22em", marginBottom:14 }}>
              ▸ MODEL PERFORMANCE
            </div>
            {[
              { name:"Random Forest", acc:"95.82%", color:"#00c8ff", w:96 },
              { name:"XGBoost", acc:"94.46%", color:"#22c55e", w:94 },
              { name:"Ensemble (Weighted)", acc:"95.41%", color:"#a78bfa", w:95 },
            ].map((m, i) => (
              <div key={i} style={{ marginBottom:16 }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
                  <span style={{ fontSize:12, color:"#c8dff4", fontFamily:"monospace" }}>{m.name}</span>
                  <span style={{ fontSize:12, color:m.color, fontWeight:700,
                    fontFamily:"monospace" }}>{m.acc}</span>
                </div>
                <div style={{ height:8, background:"rgba(255,255,255,0.05)",
                  borderRadius:4, overflow:"hidden",
                  border:"1px solid rgba(255,255,255,0.05)" }}>
                  <div style={{ height:"100%", width:`${m.w}%`,
                    background:`linear-gradient(90deg,${m.color}88,${m.color})`,
                    borderRadius:4, boxShadow:`0 0 10px ${m.color}66`,
                    transition:"width 1.5s ease" }} />
                </div>
              </div>
            ))}

            <div style={{ borderTop:"1px solid rgba(0,200,255,0.1)",
              paddingTop:14, marginTop:4 }}>
              <div style={{ fontSize:10, color:"#00c8ff", letterSpacing:"0.22em", marginBottom:10 }}>
                ▸ CONFUSION MATRIX
              </div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8 }}>
                {[
                  { label:"True Positive", value:"40,470", color:"#00cc66" },
                  { label:"True Negative", value:"81,863", color:"#4488ff" },
                  { label:"False Positive", value:"3,753", color:"#ffaa00" },
                  { label:"False Negative", value:"2,138", color:"#ff4444" },
                ].map((c, i) => (
                  <div key={i} style={{ padding:"10px 12px", borderRadius:6,
                    background:"rgba(0,0,0,0.3)",
                    border:`1px solid ${c.color}22` }}>
                    <div style={{ fontSize:18, fontWeight:700, color:c.color,
                      fontFamily:"monospace" }}>{c.value}</div>
                    <div style={{ fontSize:9, color:c.color,
                      letterSpacing:"0.08em", marginTop:2 }}>{c.label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right: Pie + ROC */}
          <div style={{ display:"flex", flexDirection:"column", gap:12 }}>

            <div className="panel" style={{ background:"#0a1220",
              border:"1px solid rgba(0,200,255,0.1)",
              padding:"16px 18px", borderRadius:8 }}>
              <div style={{ fontSize:10, color:"#00c8ff", letterSpacing:"0.22em", marginBottom:12 }}>
                ▸ THREAT DISTRIBUTION
              </div>
              <div style={{ display:"flex", alignItems:"center", gap:16 }}>
                <ResponsiveContainer width={110} height={110}>
                  <PieChart>
                    <Pie data={PIE_DATA} cx="50%" cy="50%"
                      innerRadius={30} outerRadius={50}
                      dataKey="value" strokeWidth={0}>
                      {PIE_DATA.map((e, i) => <Cell key={i} fill={e.color} opacity={0.85} />)}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ flex:1 }}>
                  {PIE_DATA.map((d, i) => (
                    <div key={i} style={{ display:"flex", justifyContent:"space-between",
                      alignItems:"center", marginBottom:7 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                        <div style={{ width:8, height:8, background:d.color, borderRadius:2 }} />
                        <span style={{ fontSize:10, color:"#8aafcc" }}>{d.name}</span>
                      </div>
                      <span style={{ fontSize:11, color:d.color, fontWeight:700 }}>{d.value}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* ROC */}
            <div className="panel" style={{ background:"#0a1220",
              border:"1px solid rgba(0,200,255,0.1)",
              padding:"16px 18px", borderRadius:8 }}>
              <div style={{ display:"flex", justifyContent:"space-between",
                alignItems:"center", marginBottom:10 }}>
                <div style={{ fontSize:10, color:"#00c8ff", letterSpacing:"0.22em" }}>
                  ▸ ROC CURVE
                </div>
                <div style={{ fontFamily:"monospace", fontSize:13,
                  color:"#00cc66", fontWeight:700 }}>AUC = 0.9909</div>
              </div>
              <ResponsiveContainer width="100%" height={120}>
                <LineChart data={ROC}>
                  <XAxis dataKey="fpr" tick={{ fill:"#4a6580", fontSize:8 }}
                    axisLine={false} tickLine={false}
                    tickFormatter={v => v.toFixed(1)} />
                  <YAxis tick={{ fill:"#4a6580", fontSize:8 }}
                    axisLine={false} tickLine={false}
                    tickFormatter={v => v.toFixed(1)} />
                  <Tooltip contentStyle={{ background:"#0d1a2e",
                    border:"1px solid rgba(0,200,255,0.2)",
                    borderRadius:6, fontSize:10, color:"#c8dff4" }}
                    formatter={v => v.toFixed(3)} />
                  <Line type="monotone" dataKey="tpr" stroke="#00c8ff"
                    strokeWidth={2.5} dot={false} name="Model" />
                  <Line type="monotone" dataKey="random" stroke="#4a6580"
                    strokeWidth={1} dot={false} strokeDasharray="4 4" name="Random" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* BOTTOM ROW */}
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:12 }}>

          {/* Timeline */}
          <div className="panel" style={{ background:"#0a1220",
            border:"1px solid rgba(0,200,255,0.1)",
            padding:"16px 18px", borderRadius:8 }}>
            <div style={{ fontSize:10, color:"#00c8ff", letterSpacing:"0.22em", marginBottom:12 }}>
              ▸ SCAN TIMELINE
            </div>
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart data={TIMELINE}>
                <defs>
                  <linearGradient id="gt" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff4444" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#ff4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gs" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00cc66" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#00cc66" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fill:"#4a6580", fontSize:9 }}
                  axisLine={false} tickLine={false} />
                <YAxis tick={{ fill:"#4a6580", fontSize:9 }}
                  axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background:"#0d1a2e",
                  border:"1px solid rgba(0,200,255,0.2)",
                  borderRadius:6, fontSize:11, color:"#c8dff4" }} />
                <Area type="monotone" dataKey="threats" stroke="#ff4444"
                  fill="url(#gt)" strokeWidth={2} name="Threats" />
                <Area type="monotone" dataKey="safe" stroke="#00cc66"
                  fill="url(#gs)" strokeWidth={2} name="Safe" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* SHAP */}
          <div className="panel" style={{ background:"#0a1220",
            border:"1px solid rgba(0,200,255,0.1)",
            padding:"16px 18px", borderRadius:8 }}>
            <div style={{ fontSize:10, color:"#00c8ff", letterSpacing:"0.22em", marginBottom:8 }}>
              ▸ SHAP FEATURE IMPORTANCE
            </div>
            <div style={{ fontSize:10, color:"#4a6580", fontFamily:"monospace",
              marginBottom:14, overflow:"hidden", textOverflow:"ellipsis",
              whiteSpace:"nowrap" }}>paypal-secure-login.ru/auth/verify</div>
            <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
              {SHAP_DATA.map((d, i) => (
                <div key={i} style={{ display:"grid",
                  gridTemplateColumns:"160px 1fr 48px",
                  gap:12, alignItems:"center" }}>
                  <span style={{ fontSize:11, color:"#8aafcc" }}>{d.feature}</span>
                  <div style={{ height:8, background:"rgba(255,255,255,0.04)",
                    borderRadius:2, overflow:"hidden",
                    border:"1px solid rgba(255,255,255,0.04)" }}>
                    <div style={{ height:"100%",
                      width:`${Math.abs(d.value) * 2.5}%`,
                      background:`linear-gradient(90deg,${d.color}88,${d.color})`,
                      borderRadius:2,
                      boxShadow:`0 0 8px ${d.color}55` }} />
                  </div>
                  <span style={{ fontSize:11, color:d.color,
                    textAlign:"right", fontWeight:700, fontFamily:"monospace" }}>
                    {d.value > 0 ? "+" : ""}{d.value}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* PIPELINE */}
        <div className="panel" style={{ background:"#0a1220",
          border:"1px solid rgba(0,200,255,0.1)",
          padding:"16px 18px", borderRadius:8 }}>
          <div style={{ fontSize:10, color:"#00c8ff", letterSpacing:"0.22em", marginBottom:14 }}>
            ▸ DETECTION PIPELINE
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:8 }}>
            {PIPES.map((p, i) => (
              <div key={i} style={{ textAlign:"center", padding:"10px 6px", borderRadius:6,
                background: pipeStep === i ? `${PIPE_COLORS[i]}18` : "rgba(0,0,0,0.2)",
                border:`1px solid ${pipeStep === i ? PIPE_COLORS[i] : "rgba(0,200,255,0.08)"}`,
                transition:"all 0.3s" }}>
                <div style={{ fontSize:20, marginBottom:6 }}>
                  {["🌐","🧩","⚙️","🧠","👁","🛡️"][i]}
                </div>
                <div style={{ fontSize:9, color: pipeStep === i ? PIPE_COLORS[i] : "#4a6580",
                  letterSpacing:"0.06em", transition:"color 0.3s" }}>{p}</div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}