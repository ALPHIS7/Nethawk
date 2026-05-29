/**
 * CFCIA — Cloudflare Clean IP Attacher
 * Scans Cloudflare IP ranges, finds clean/fast IPs,
 * then patches V2Ray / Trojan / VLESS / VMess configs
 * with the best discovered endpoint.
 */

import { useState, useEffect, useRef, useCallback, useMemo } from "react";

/* ═══════════════════════════════════════════════════════════════
   CLOUDFLARE IP RANGES (official AS13335 subnets)
═══════════════════════════════════════════════════════════════ */
const CF_RANGES = [
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "108.162.192.0/18",
  "131.0.72.0/22",
  "141.101.64.0/18",
  "162.158.0.0/15",
  "172.64.0.0/13",
  "173.245.48.0/20",
  "188.114.96.0/20",
  "190.93.240.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
];

/* Well-known Cloudflare test IPs grouped by region */
const CF_TEST_IPS: Record<string, string[]> = {
  "Americas": [
    "104.16.0.1","104.16.1.1","104.17.0.1","104.18.0.1","104.19.0.1",
    "104.20.0.1","104.21.0.1","104.22.0.1","104.23.0.1","104.24.0.1",
    "172.64.0.1","172.65.0.1","172.66.0.1","172.67.0.1","172.68.0.1",
  ],
  "Europe": [
    "141.101.64.1","141.101.65.1","141.101.66.1","141.101.67.1",
    "188.114.96.1","188.114.97.1","188.114.98.1","188.114.99.1",
    "190.93.240.1","190.93.241.1","190.93.242.1","190.93.243.1",
  ],
  "Asia-Pacific": [
    "103.21.244.1","103.21.245.1","103.21.246.1","103.21.247.1",
    "103.22.200.1","103.22.201.1","103.22.202.1","103.22.203.1",
    "103.31.4.1","103.31.5.1","103.31.6.1","103.31.7.1",
    "131.0.72.1","131.0.73.1","131.0.74.1","131.0.75.1",
  ],
  "Core": [
    "1.1.1.1","1.0.0.1","1.1.1.2","1.0.0.2",
    "162.158.0.1","162.158.1.1","162.159.0.1","162.159.1.1",
    "198.41.128.1","198.41.129.1","198.41.130.1","198.41.131.1",
  ],
};

/* ═══════════════════════════════════════════════════════════════
   TYPES
═══════════════════════════════════════════════════════════════ */
interface ScanResult {
  ip: string;
  latency: number | null;
  status: "clean" | "slow" | "timeout" | "scanning";
  region: string;
  loss: number;
  jitter: number;
  score: number;
}

interface ParsedConfig {
  protocol: "vmess" | "vless" | "trojan" | "ss" | "ssr" | "unknown";
  raw: string;
  address: string;
  port: number | string;
  displayName: string;
}

type ScanPhase = "idle" | "scanning" | "done";
type WizardStep = "scan" | "paste" | "result";

/* ═══════════════════════════════════════════════════════════════
   CONFIG PARSER
═══════════════════════════════════════════════════════════════ */
function parseConfig(raw: string): ParsedConfig | null {
  const trimmed = raw.trim();

  // VMess
  if (trimmed.startsWith("vmess://")) {
    try {
      const b64 = trimmed.slice(8);
      const json = JSON.parse(atob(b64));
      return {
        protocol: "vmess",
        raw: trimmed,
        address: json.add || json.host || "",
        port: json.port || 443,
        displayName: json.ps || json.remarks || `VMess@${json.add}`,
      };
    } catch {
      return null;
    }
  }

  // VLESS
  if (trimmed.startsWith("vless://")) {
    try {
      const url = new URL(trimmed.replace("vless://", "http://"));
      const frag = decodeURIComponent(trimmed.split("#")[1] || "");
      return {
        protocol: "vless",
        raw: trimmed,
        address: url.hostname,
        port: url.port || 443,
        displayName: frag || `VLESS@${url.hostname}`,
      };
    } catch {
      return null;
    }
  }

  // Trojan
  if (trimmed.startsWith("trojan://")) {
    try {
      const url = new URL(trimmed.replace("trojan://", "http://"));
      const frag = decodeURIComponent(trimmed.split("#")[1] || "");
      return {
        protocol: "trojan",
        raw: trimmed,
        address: url.hostname,
        port: url.port || 443,
        displayName: frag || `Trojan@${url.hostname}`,
      };
    } catch {
      return null;
    }
  }

  // Shadowsocks
  if (trimmed.startsWith("ss://")) {
    try {
      const url = new URL(trimmed.replace("ss://", "http://"));
      const frag = decodeURIComponent(trimmed.split("#")[1] || "");
      return {
        protocol: "ss",
        raw: trimmed,
        address: url.hostname,
        port: url.port || 443,
        displayName: frag || `SS@${url.hostname}`,
      };
    } catch {
      return null;
    }
  }

  // ShadowsocksR
  if (trimmed.startsWith("ssr://")) {
    return {
      protocol: "ssr",
      raw: trimmed,
      address: "embedded",
      port: "?",
      displayName: "SSR Config",
    };
  }

  // Generic URI
  if (trimmed.includes("://")) {
    try {
      const url = new URL(trimmed.split("#")[0]);
      return {
        protocol: "unknown",
        raw: trimmed,
        address: url.hostname,
        port: url.port || 443,
        displayName: `Config@${url.hostname}`,
      };
    } catch {
      return null;
    }
  }

  return null;
}

/* ═══════════════════════════════════════════════════════════════
   CONFIG PATCHER
  Replaces the IP/host in the config string with a new IP
═══════════════════════════════════════════════════════════════ */
function patchConfig(parsed: ParsedConfig, newIp: string): string {
  const { protocol, raw, address } = parsed;

  if (!address || address === "embedded") return raw;

  // VMess: decode → change add → re-encode
  if (protocol === "vmess") {
    try {
      const b64 = raw.slice(8);
      const json = JSON.parse(atob(b64));
      if (json.add) json.add = newIp;
      if (json.host && json.host === address) json.host = newIp;
      const newB64 = btoa(JSON.stringify(json));
      return `vmess://${newB64}`;
    } catch {
      return raw;
    }
  }

  // For all others: simple string replacement of the host
  // Be careful to replace only the host part, not fragment or path
  const escaped = address.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // Replace hostname in URI (after :// and before : or / or ? or #)
  const hostRegex = new RegExp(
    `((?:vless|trojan|ss|ssr|http|https):\\/\\/[^@]*@?)${escaped}(:\\d+)?`,
    "g"
  );
  let patched = raw.replace(hostRegex, (_, prefix, portPart) => {
    return `${prefix}${newIp}${portPart || ""}`;
  });

  // Fallback: plain replace if regex didn't catch
  if (patched === raw) {
    patched = raw.split(address).join(newIp);
  }

  return patched;
}

/* ═══════════════════════════════════════════════════════════════
   SIMULATED SCANNER (browser can't do raw TCP/ICMP)
   Uses fetch to CF's edge to estimate latency realistically.
   In a real Electron/Tauri app this would use native sockets.
═══════════════════════════════════════════════════════════════ */
async function probeIp(ip: string, region: string): Promise<ScanResult> {
  const start = performance.now();
  let latency: number | null = null;
  let loss = 0;
  let jitter = 0;

  try {
    // Try fetching CF's /cdn-cgi/trace through their IPs
    // This works in browser for actual CF IPs
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);

    await fetch(`https://${ip}/cdn-cgi/trace`, {
      signal: ctrl.signal,
      mode: "no-cors",
      cache: "no-store",
    });
    clearTimeout(timer);

    latency = Math.round(performance.now() - start);

    // Simulate a few more probes for jitter/loss calculation
    const probes: number[] = [latency];
    for (let i = 0; i < 2; i++) {
      const s2 = performance.now();
      try {
        const c2 = new AbortController();
        const t2 = setTimeout(() => c2.abort(), 2000);
        await fetch(`https://${ip}/cdn-cgi/trace`, { signal: c2.signal, mode: "no-cors", cache: "no-store" });
        clearTimeout(t2);
        probes.push(Math.round(performance.now() - s2));
      } catch {
        loss += 33;
      }
    }
    const avg = probes.reduce((a, b) => a + b, 0) / probes.length;
    jitter = Math.round(Math.max(...probes) - Math.min(...probes));
    latency = Math.round(avg);

  } catch {
    latency = null;
    loss = 100;
  }

  const status: ScanResult["status"] =
    latency === null ? "timeout" :
    latency < 150 ? "clean" :
    "slow";

  const score = latency === null ? 0 :
    Math.max(0, 100 - Math.round(latency / 5) - Math.round(loss / 2) - Math.round(jitter / 10));

  return { ip, latency, status, region, loss, jitter, score };
}

/* ═══════════════════════════════════════════════════════════════
   CFCIA COMPONENT
═══════════════════════════════════════════════════════════════ */
interface CFCIAProps {
  cssVars?: string;
}

export default function CFCIA(_props: CFCIAProps) {
  /* ── state ── */
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [step, setStep] = useState<WizardStep>("scan");
  const [results, setResults] = useState<ScanResult[]>([]);
  const [scanning, setScanning] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [configInput, setConfigInput] = useState("");
  const [parsedConfig, setParsedConfig] = useState<ParsedConfig | null>(null);
  const [parseError, setParseError] = useState("");
  const [patchedConfigs, setPatchedConfigs] = useState<{ config: string; ip: string }[]>([]);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [regionFilter, setRegionFilter] = useState<string>("All");
  const [sortBy, setSortBy] = useState<"score" | "latency" | "region">("score");
  const [logLines, setLogLines] = useState<{ msg: string; type: string; id: number }[]>([]);
  const [concurrency] = useState(6);
  const [threshold, setThreshold] = useState(200);
  const [topN, setTopN] = useState(5);

  const logRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef(false);

  /* ── helpers ── */
  const addLog = useCallback((msg: string, type = "dim") => {
    setLogLines(l => [...l.slice(-80), { msg, type, id: Date.now() + Math.random() }]);
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logLines]);

  /* ── collect all IPs to scan ── */
  const allIps = useMemo(() => {
    const list: { ip: string; region: string }[] = [];
    Object.entries(CF_TEST_IPS).forEach(([region, ips]) => {
      ips.forEach(ip => list.push({ ip, region }));
    });
    return list;
  }, []);

  /* ── start scan ── */
  const startScan = useCallback(async () => {
    abortRef.current = false;
    setPhase("scanning");
    setResults([]);
    setProgress(0);
    setLogLines([]);
    addLog("⚡ CFCIA Scanner initialized", "ok");
    addLog(`Targeting ${allIps.length} Cloudflare IPs across ${Object.keys(CF_TEST_IPS).length} regions`, "dim");
    addLog(`Concurrency: ${concurrency} · Threshold: ${threshold}ms · Top-N: ${topN}`, "dim");
    addLog("─".repeat(50), "dim");

    const total = allIps.length;
    let done = 0;
    const batchSize = concurrency;

    for (let i = 0; i < total; i += batchSize) {
      if (abortRef.current) break;

      const batch = allIps.slice(i, i + batchSize);
      setScanning(batch.map(b => b.ip));

      const batchResults = await Promise.all(
        batch.map(({ ip, region }) => probeIp(ip, region))
      );

      batchResults.forEach(r => {
        if (r.status === "clean") {
          addLog(`✓ CLEAN  ${r.ip.padEnd(17)} ${r.region.padEnd(14)} ${r.latency}ms  jitter:${r.jitter}ms  loss:${r.loss}%  score:${r.score}`, "found");
        } else if (r.status === "slow") {
          addLog(`~ SLOW   ${r.ip.padEnd(17)} ${r.region.padEnd(14)} ${r.latency}ms`, "warn");
        } else {
          addLog(`✗ TIMEOUT ${r.ip.padEnd(16)} ${r.region}`, "dead");
        }
      });

      setResults(prev => [...prev, ...batchResults]);
      done += batch.length;
      setProgress(Math.round((done / total) * 100));
    }

    setScanning([]);
    setPhase("done");

    const clean = [...results, ...[]].filter(r => r.status === "clean");
    addLog("─".repeat(50), "dim");
    addLog(`✓ Scan complete — ${clean.length} clean IPs found`, "ok");
  }, [allIps, concurrency, threshold, topN, addLog, results]);

  const stopScan = () => {
    abortRef.current = true;
    setPhase("done");
    setScanning([]);
    addLog("⚠ Scan aborted by user", "warn");
  };

  /* ── sorted / filtered results ── */
  const displayResults = useMemo(() => {
    let list = results.filter(r => r.status !== "timeout");
    if (regionFilter !== "All") list = list.filter(r => r.region === regionFilter);
    list.sort((a, b) => {
      if (sortBy === "score") return b.score - a.score;
      if (sortBy === "latency") return (a.latency ?? 9999) - (b.latency ?? 9999);
      return a.region.localeCompare(b.region);
    });
    return list;
  }, [results, regionFilter, sortBy]);

  const cleanResults = useMemo(() =>
    displayResults.filter(r => r.status === "clean" && (r.latency ?? 9999) <= threshold),
    [displayResults, threshold]
  );

  const topIps = useMemo(() => cleanResults.slice(0, topN), [cleanResults, topN]);

  /* ── parse config input ── */
  const handleParseConfig = () => {
    setParseError("");
    setParsedConfig(null);
    const lines = configInput.trim().split("\n").filter(l => l.trim());

    // Support multi-line (one config per line)
    const parsed = lines.map(l => parseConfig(l.trim())).filter(Boolean) as ParsedConfig[];

    if (parsed.length === 0) {
      setParseError("❌ Could not parse config. Make sure it starts with vmess://, vless://, trojan://, or ss://");
      return;
    }

    // Use first valid config
    setParsedConfig(parsed[0]);
  };

  /* ── patch configs ── */
  const handlePatch = () => {
    if (!parsedConfig) return;
    const ips = selectedIp ? [selectedIp] : topIps.map(r => r.ip);
    const patched = ips.map(ip => ({
      ip,
      config: patchConfig(parsedConfig, ip),
    }));
    setPatchedConfigs(patched);
    setStep("result");
  };

  const copyToClipboard = (text: string, idx: number) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedIdx(idx);
      setTimeout(() => setCopiedIdx(null), 2000);
    });
  };

  /* ── regions for filter ── */
  const regions = useMemo(() =>
    ["All", ...Array.from(new Set(results.map(r => r.region)))],
    [results]
  );

  /* ── protocol badge color ── */
  const protocolColor = (p: string) => ({
    vmess: "#a855f7", vless: "#00e5ff", trojan: "#f97316",
    ss: "#eab308", ssr: "#94a3b8", unknown: "#64748b",
  }[p] || "#64748b");

  /* ════════════════════════════════════════════════════════════
     RENDER
  ════════════════════════════════════════════════════════════ */
  return (
    <div className="page-enter">

      {/* ── Header banner ── */}
      <div className="card" style={{ marginBottom: 14, borderColor: "rgba(0,229,255,0.2)", background: "linear-gradient(135deg, #0d1220 0%, #0a111f 100%)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
          <div>
            <div style={{ fontFamily: "var(--font-head)", fontSize: 18, fontWeight: 900, color: "var(--cyan)", letterSpacing: 3, textShadow: "0 0 20px rgba(0,229,255,0.4)", marginBottom: 6 }}>
              CFCIA
            </div>
            <div style={{ fontFamily: "var(--font-data)", fontSize: 10, color: "var(--text-3)", letterSpacing: 2, marginBottom: 8 }}>
              CLOUDFLARE CLEAN IP ATTACHER
            </div>
            <div style={{ fontFamily: "var(--font-ui)", fontSize: 12, color: "var(--text-2)", lineHeight: 1.7, maxWidth: 560 }}>
              Scans Cloudflare's IP ranges to find the fastest, cleanest endpoints,
              then automatically patches your V2Ray / VLESS / Trojan / Shadowsocks configs
              with the optimal IP.
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, alignItems: "flex-end" }}>
            <div style={{ fontFamily: "var(--font-data)", fontSize: 10, color: "var(--text-3)" }}>
              {allIps.length} IPs · {Object.keys(CF_TEST_IPS).length} regions
            </div>
            <div style={{ display: "flex", gap: 6 }}>
              {["SCAN", "CONFIGURE", "PATCH"].map((s, i) => (
                <div key={s} style={{
                  fontFamily: "var(--font-data)", fontSize: 9, padding: "3px 10px",
                  borderRadius: 3, letterSpacing: 1,
                  background: i === (step === "scan" ? 0 : step === "paste" ? 1 : 2) ? "rgba(0,229,255,0.15)" : "transparent",
                  border: `1px solid ${i === (step === "scan" ? 0 : step === "paste" ? 1 : 2) ? "var(--cyan)" : "var(--border-dim)"}`,
                  color: i === (step === "scan" ? 0 : step === "paste" ? 1 : 2) ? "var(--cyan)" : "var(--text-3)",
                }}>
                  {i + 1}. {s}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ══════════════════════════════════════
          STEP 1 — SCAN
      ══════════════════════════════════════ */}
      {step === "scan" && (
        <>
          {/* Config panel */}
          <div className="card" style={{ marginBottom: 14 }}>
            <div className="card-title">SCAN CONFIGURATION</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 14 }}>
              <div>
                <div className="input-label">LATENCY THRESHOLD (ms)</div>
                <div className="range-wrap">
                  <input type="range" className="range-input" min={50} max={1000} step={50}
                    value={threshold} onChange={e => setThreshold(+e.target.value)} />
                  <span className="range-val">{threshold}</span>
                </div>
                <div style={{ fontSize: 10, fontFamily: "var(--font-data)", color: "var(--text-3)", marginTop: 4 }}>
                  IPs below this are marked "clean"
                </div>
              </div>
              <div>
                <div className="input-label">TOP-N IPs TO PATCH</div>
                <div className="range-wrap">
                  <input type="range" className="range-input" min={1} max={10} step={1}
                    value={topN} onChange={e => setTopN(+e.target.value)} />
                  <span className="range-val">{topN}</span>
                </div>
                <div style={{ fontSize: 10, fontFamily: "var(--font-data)", color: "var(--text-3)", marginTop: 4 }}>
                  Best N IPs will be used for patching
                </div>
              </div>
              <div>
                <div className="input-label">SORT RESULTS BY</div>
                <select className="select-field" style={{ width: "100%" }} value={sortBy}
                  onChange={e => setSortBy(e.target.value as any)}>
                  <option value="score">Score (recommended)</option>
                  <option value="latency">Latency (fastest first)</option>
                  <option value="region">Region</option>
                </select>
              </div>
            </div>

            <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
              {phase === "idle" || phase === "done" ? (
                <button className="btn btn-primary" style={{ borderColor: "var(--cyan)", color: "var(--cyan)", background: "rgba(0,229,255,0.1)" }}
                  onClick={startScan}>
                  <svg viewBox="0 0 24 24" fill="currentColor" width="12" height="12"><polygon points="5 3 19 12 5 21 5 3" /></svg>
                  {phase === "done" ? "RESCAN" : "START SCAN"}
                </button>
              ) : (
                <button className="btn btn-danger btn-sm" onClick={stopScan}>
                  <svg viewBox="0 0 24 24" fill="currentColor" width="12" height="12"><rect x="3" y="3" width="18" height="18" rx="2" /></svg>
                  ABORT SCAN
                </button>
              )}

              {phase === "done" && cleanResults.length > 0 && (
                <button className="btn btn-primary" style={{ borderColor: "var(--green)", color: "var(--green)", background: "rgba(0,255,157,0.1)" }}
                  onClick={() => setStep("paste")}>
                  NEXT: PASTE CONFIG →
                </button>
              )}

              <div style={{ flex: 1 }} />

              {phase !== "idle" && (
                <div style={{ fontFamily: "var(--font-data)", fontSize: 11, display: "flex", gap: 16, color: "var(--text-3)" }}>
                  <span>Scanned: <span style={{ color: "var(--text-2)" }}>{results.length}/{allIps.length}</span></span>
                  <span>Clean: <span style={{ color: "var(--green)" }}>{cleanResults.length}</span></span>
                  <span>Slow: <span style={{ color: "var(--yellow)" }}>{results.filter(r => r.status === "slow").length}</span></span>
                  <span>Timeout: <span style={{ color: "var(--red)" }}>{results.filter(r => r.status === "timeout").length}</span></span>
                </div>
              )}
            </div>
          </div>

          {/* Progress */}
          {phase !== "idle" && (
            <div className="card" style={{ marginBottom: 14 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                <div className="card-title" style={{ marginBottom: 0 }}>
                  {phase === "scanning" ? (
                    <span style={{ color: "var(--cyan)" }}>
                      ⚡ SCANNING CLOUDFLARE IPs...
                    </span>
                  ) : "SCAN COMPLETE"}
                </div>
                <div style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--cyan)" }}>{progress}%</div>
              </div>
              <div className="progress-wrap">
                <div className="progress-bar" style={{
                  width: `${progress}%`,
                  background: "linear-gradient(90deg, var(--cyan), var(--green))"
                }} />
              </div>

              {/* Currently scanning */}
              {scanning.length > 0 && (
                <div style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {scanning.map(ip => (
                    <span key={ip} style={{
                      fontFamily: "var(--font-data)", fontSize: 9, padding: "2px 8px",
                      borderRadius: 3, border: "1px solid rgba(0,229,255,0.3)",
                      color: "var(--cyan)", background: "rgba(0,229,255,0.08)",
                      animation: "btn-pulse 1.5s infinite"
                    }}>
                      {ip}
                    </span>
                  ))}
                </div>
              )}

              {/* Terminal log */}
              <div ref={logRef} className="terminal-log" style={{ height: 130, marginTop: 12 }}>
                {logLines.map(l => (
                  <div key={l.id} style={{
                    color: l.type === "ok" ? "var(--green)" : l.type === "found" ? "var(--green)" :
                      l.type === "warn" ? "var(--yellow)" : l.type === "dead" ? "var(--red)" : "var(--text-3)"
                  }}>
                    {l.msg}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Results table */}
          {displayResults.length > 0 && (
            <div className="card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
                <div className="card-title" style={{ marginBottom: 0 }}>
                  SCAN RESULTS —&nbsp;
                  <span style={{ color: "var(--green)" }}>{cleanResults.length} CLEAN</span>
                  &nbsp;/&nbsp;
                  <span style={{ color: "var(--text-2)" }}>{displayResults.length} TOTAL</span>
                </div>
                <select className="select-field" value={regionFilter}
                  onChange={e => setRegionFilter(e.target.value)}>
                  {regions.map(r => <option key={r}>{r}</option>)}
                </select>
              </div>

              <div style={{ overflowX: "auto" }}>
                <table className="device-table">
                  <thead>
                    <tr>
                      <th>IP ADDRESS</th>
                      <th>REGION</th>
                      <th>LATENCY</th>
                      <th>JITTER</th>
                      <th>LOSS %</th>
                      <th>SCORE</th>
                      <th>STATUS</th>
                      <th>ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayResults.map((r, idx) => (
                      <tr key={r.ip} style={{ background: selectedIp === r.ip ? "rgba(0,229,255,0.06)" : undefined }}>
                        <td className="ip-cell" style={{ color: "var(--cyan)" }}>
                          {idx < topN && r.status === "clean" && (r.latency ?? 9999) <= threshold && (
                            <span style={{
                              fontSize: 8, padding: "1px 5px", marginRight: 6,
                              borderRadius: 2, background: "rgba(0,255,157,0.15)",
                              border: "1px solid rgba(0,255,157,0.3)", color: "var(--green)"
                            }}>TOP</span>
                          )}
                          {r.ip}
                        </td>
                        <td style={{ color: "var(--text-2)", fontSize: 10 }}>{r.region}</td>
                        <td style={{
                          fontFamily: "var(--font-data)", fontSize: 11,
                          color: !r.latency ? "var(--red)" : r.latency < 100 ? "var(--green)" : r.latency < 200 ? "var(--yellow)" : "var(--orange)"
                        }}>
                          {r.latency ? `${r.latency}ms` : "—"}
                        </td>
                        <td style={{ fontFamily: "var(--font-data)", fontSize: 10, color: "var(--text-3)" }}>
                          {r.jitter ? `±${r.jitter}ms` : "—"}
                        </td>
                        <td style={{ fontFamily: "var(--font-data)", fontSize: 10, color: r.loss > 0 ? "var(--yellow)" : "var(--text-3)" }}>
                          {r.loss}%
                        </td>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <div style={{
                              height: 4, width: `${r.score}%`, maxWidth: 60,
                              background: r.score > 70 ? "var(--green)" : r.score > 40 ? "var(--yellow)" : "var(--red)",
                              borderRadius: 2, minWidth: 4
                            }} />
                            <span style={{ fontFamily: "var(--font-data)", fontSize: 10, color: "var(--text-2)" }}>{r.score}</span>
                          </div>
                        </td>
                        <td>
                          <span className={`status-badge ${r.status === "clean" ? "online" : "offline"}`}
                            style={r.status === "slow" ? { background: "rgba(234,179,8,0.1)", borderColor: "rgba(234,179,8,0.3)", color: "var(--yellow)" } : {}}>
                            <span className="dot" />
                            {r.status.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <button className="btn btn-secondary btn-sm"
                            style={selectedIp === r.ip ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}}
                            onClick={() => setSelectedIp(selectedIp === r.ip ? null : r.ip)}>
                            {selectedIp === r.ip ? "✓ SELECTED" : "SELECT"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {phase === "done" && cleanResults.length > 0 && (
                <div style={{ marginTop: 14, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                  <div style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--text-2)" }}>
                    {selectedIp
                      ? <span>Using selected IP: <span style={{ color: "var(--cyan)" }}>{selectedIp}</span></span>
                      : <span>Will use top <span style={{ color: "var(--green)" }}>{topN}</span> clean IPs automatically</span>
                    }
                  </div>
                  <div style={{ flex: 1 }} />
                  <button className="btn btn-primary" style={{ borderColor: "var(--green)", color: "var(--green)", background: "rgba(0,255,157,0.1)" }}
                    onClick={() => setStep("paste")}>
                    NEXT: PASTE YOUR CONFIG →
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Empty state */}
          {phase === "idle" && (
            <div className="card" style={{ textAlign: "center", padding: "48px 24px" }}>
              <div style={{ fontSize: 40, marginBottom: 16 }}>⚡</div>
              <div style={{ fontFamily: "var(--font-head)", fontSize: 13, letterSpacing: 2, color: "var(--text-2)", marginBottom: 8 }}>
                READY TO SCAN
              </div>
              <div style={{ fontFamily: "var(--font-ui)", fontSize: 12, color: "var(--text-3)", lineHeight: 1.7, maxWidth: 400, margin: "0 auto" }}>
                Press <span style={{ color: "var(--cyan)" }}>START SCAN</span> to probe Cloudflare's IP ranges
                and find the fastest, cleanest endpoints for your location.
              </div>
              <div style={{ marginTop: 20, display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap" }}>
                {CF_RANGES.slice(0, 6).map(r => (
                  <span key={r} style={{
                    fontFamily: "var(--font-data)", fontSize: 9, padding: "3px 8px",
                    borderRadius: 3, border: "1px solid var(--border-dim)", color: "var(--text-3)"
                  }}>{r}</span>
                ))}
                <span style={{ fontFamily: "var(--font-data)", fontSize: 9, color: "var(--text-3)" }}>+{CF_RANGES.length - 6} more</span>
              </div>
            </div>
          )}
        </>
      )}

      {/* ══════════════════════════════════════
          STEP 2 — PASTE CONFIG
      ══════════════════════════════════════ */}
      {step === "paste" && (
        <>
          {/* Back button */}
          <div style={{ marginBottom: 14 }}>
            <button className="btn btn-secondary btn-sm" onClick={() => setStep("scan")}>
              ← BACK TO RESULTS
            </button>
          </div>

          {/* Selected IPs summary */}
          <div className="card" style={{ marginBottom: 14, borderColor: "rgba(0,255,157,0.2)" }}>
            <div className="card-title">SELECTED CLEAN IPs</div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {(selectedIp ? [cleanResults.find(r => r.ip === selectedIp)!].filter(Boolean) : topIps).map(r => (
                <div key={r.ip} style={{
                  fontFamily: "var(--font-data)", fontSize: 10, padding: "5px 12px",
                  borderRadius: 4, border: "1px solid rgba(0,255,157,0.3)",
                  background: "rgba(0,255,157,0.06)", color: "var(--green)",
                  display: "flex", alignItems: "center", gap: 8
                }}>
                  <span className="status-dot" style={{ width: 5, height: 5 }} />
                  {r.ip}
                  <span style={{ color: "var(--text-3)", fontSize: 9 }}>{r.latency}ms</span>
                  <span style={{ color: "var(--text-3)", fontSize: 9 }}>{r.region}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Config input */}
          <div className="card" style={{ marginBottom: 14 }}>
            <div className="card-title">PASTE YOUR CONFIG</div>
            <div style={{ marginBottom: 10 }}>
              <div className="input-label">SUPPORTED FORMATS</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
                {[["vmess://", "#a855f7"], ["vless://", "#00e5ff"], ["trojan://", "#f97316"], ["ss://", "#eab308"], ["ssr://", "#94a3b8"]].map(([p, c]) => (
                  <span key={p} style={{
                    fontFamily: "var(--font-data)", fontSize: 9, padding: "2px 8px",
                    borderRadius: 3, border: `1px solid ${c}44`, color: c,
                    background: `${c}11`
                  }}>{p}</span>
                ))}
              </div>
            </div>
            <textarea
              value={configInput}
              onChange={e => { setConfigInput(e.target.value); setParseError(""); setParsedConfig(null); }}
              placeholder={`Paste your config here, for example:
vmess://eyJhZGQiOiAiMTA0LjE2LjAuMSIsICJwb3J0IjogNDQzLCAuLi59
vless://uuid@1.2.3.4:443?encryption=none&security=tls#MyProxy
trojan://password@1.2.3.4:443#MyTrojan`}
              style={{
                width: "100%", height: 160,
                background: "var(--bg-input)",
                border: `1px solid ${parseError ? "var(--red)" : parsedConfig ? "var(--green)" : "var(--border-dim)"}`,
                borderRadius: 5, padding: "12px 14px",
                fontFamily: "var(--font-data)", fontSize: 11,
                color: "var(--text-1)", outline: "none", resize: "vertical",
                transition: "border-color 0.2s"
              }}
            />
            {parseError && (
              <div style={{ marginTop: 8, fontFamily: "var(--font-data)", fontSize: 11, color: "var(--red)" }}>
                {parseError}
              </div>
            )}
            {parsedConfig && (
              <div style={{
                marginTop: 10, padding: "10px 14px", borderRadius: 5,
                background: "rgba(0,255,157,0.04)", border: "1px solid rgba(0,255,157,0.2)"
              }}>
                <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
                  <span style={{
                    fontFamily: "var(--font-data)", fontSize: 10, padding: "2px 8px",
                    borderRadius: 3, border: `1px solid ${protocolColor(parsedConfig.protocol)}44`,
                    color: protocolColor(parsedConfig.protocol),
                    background: `${protocolColor(parsedConfig.protocol)}11`,
                    textTransform: "uppercase"
                  }}>{parsedConfig.protocol}</span>
                  <span style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--text-2)" }}>
                    Host: <span style={{ color: "var(--cyan)" }}>{parsedConfig.address}</span>
                  </span>
                  <span style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--text-2)" }}>
                    Port: <span style={{ color: "var(--text-1)" }}>{parsedConfig.port}</span>
                  </span>
                  <span style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--green)" }}>
                    ✓ Valid config detected
                  </span>
                </div>
                <div style={{ marginTop: 6, fontFamily: "var(--font-data)", fontSize: 10, color: "var(--text-3)" }}>
                  {parsedConfig.displayName}
                </div>
              </div>
            )}

            <div style={{ display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
              {!parsedConfig ? (
                <button className="btn btn-primary" style={{ borderColor: "var(--cyan)", color: "var(--cyan)", background: "rgba(0,229,255,0.1)" }}
                  onClick={handleParseConfig} disabled={!configInput.trim()}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="11" height="11"><polyline points="20 6 9 17 4 12" /></svg>
                  PARSE CONFIG
                </button>
              ) : (
                <button className="btn btn-primary" style={{ borderColor: "var(--green)", color: "var(--green)", background: "rgba(0,255,157,0.1)" }}
                  onClick={handlePatch}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="11" height="11"><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" /></svg>
                  PATCH & GENERATE →
                </button>
              )}
              <button className="btn btn-secondary btn-sm" onClick={() => { setConfigInput(""); setParsedConfig(null); setParseError(""); }}>
                CLEAR
              </button>
            </div>
          </div>

          {/* How it works */}
          <div className="card" style={{ borderColor: "var(--border-dim)" }}>
            <div className="card-title">HOW IT WORKS</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
              {[
                { n: "1", t: "Scan", d: "CFCIA probes Cloudflare's IP ranges using real HTTP requests to find low-latency, low-loss endpoints." },
                { n: "2", t: "Parse", d: "Your config URI is decoded — host/IP is extracted from vmess JSON, or directly from the URI." },
                { n: "3", t: "Patch", d: "The original host in your config is replaced with the best clean Cloudflare IP(s) found. Ready to import!" },
              ].map(s => (
                <div key={s.n} style={{ display: "flex", gap: 12 }}>
                  <div style={{
                    width: 28, height: 28, borderRadius: "50%", flexShrink: 0,
                    background: "rgba(0,229,255,0.1)", border: "1px solid rgba(0,229,255,0.3)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontFamily: "var(--font-head)", fontSize: 11, color: "var(--cyan)"
                  }}>{s.n}</div>
                  <div>
                    <div style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--text-1)", marginBottom: 4 }}>{s.t}</div>
                    <div style={{ fontFamily: "var(--font-ui)", fontSize: 11, color: "var(--text-3)", lineHeight: 1.6 }}>{s.d}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {/* ══════════════════════════════════════
          STEP 3 — RESULT
      ══════════════════════════════════════ */}
      {step === "result" && (
        <>
          <div style={{ marginBottom: 14, display: "flex", gap: 10 }}>
            <button className="btn btn-secondary btn-sm" onClick={() => setStep("paste")}>
              ← BACK
            </button>
            <button className="btn btn-secondary btn-sm" onClick={() => { setStep("scan"); setPhase("idle"); setResults([]); setProgress(0); setLogLines([]); setPatchedConfigs([]); setParsedConfig(null); setConfigInput(""); setSelectedIp(null); }}>
              ↺ START OVER
            </button>
          </div>

          {/* Success banner */}
          <div className="card" style={{ marginBottom: 14, borderColor: "rgba(0,255,157,0.4)", background: "rgba(0,255,157,0.03)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <div style={{ fontSize: 32 }}>✅</div>
              <div>
                <div style={{ fontFamily: "var(--font-head)", fontSize: 13, letterSpacing: 2, color: "var(--green)", marginBottom: 4 }}>
                  CONFIGS PATCHED SUCCESSFULLY
                </div>
                <div style={{ fontFamily: "var(--font-ui)", fontSize: 12, color: "var(--text-2)" }}>
                  {patchedConfigs.length} config{patchedConfigs.length > 1 ? "s" : ""} generated with clean Cloudflare IPs.
                  Copy and import into your client app.
                </div>
              </div>
            </div>
          </div>

          {/* Original config info */}
          {parsedConfig && (
            <div className="card" style={{ marginBottom: 14 }}>
              <div className="card-title">ORIGINAL CONFIG</div>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
                <span style={{
                  fontFamily: "var(--font-data)", fontSize: 10, padding: "2px 8px",
                  borderRadius: 3, border: `1px solid ${protocolColor(parsedConfig.protocol)}44`,
                  color: protocolColor(parsedConfig.protocol), background: `${protocolColor(parsedConfig.protocol)}11`,
                  textTransform: "uppercase"
                }}>{parsedConfig.protocol}</span>
                <span style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--text-2)" }}>
                  Original host: <span style={{ color: "var(--red)" }}>{parsedConfig.address}</span>
                </span>
                <span style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--text-2)" }}>
                  Port: <span style={{ color: "var(--text-1)" }}>{parsedConfig.port}</span>
                </span>
                <span style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--text-3)" }}>
                  → replaced with {patchedConfigs.length} clean IP{patchedConfigs.length > 1 ? "s" : ""}
                </span>
              </div>
            </div>
          )}

          {/* Patched configs */}
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {patchedConfigs.map((pc, idx) => {
              const r = cleanResults.find(r => r.ip === pc.ip);
              return (
                <div key={pc.ip} className="card" style={{
                  borderColor: idx === 0 ? "rgba(0,255,157,0.3)" : "var(--border-dim)"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      {idx === 0 && (
                        <span style={{
                          fontFamily: "var(--font-data)", fontSize: 9, padding: "2px 8px",
                          borderRadius: 3, background: "rgba(0,255,157,0.15)",
                          border: "1px solid rgba(0,255,157,0.4)", color: "var(--green)"
                        }}>⭐ BEST</span>
                      )}
                      <span style={{ fontFamily: "var(--font-data)", fontSize: 13, color: "var(--cyan)" }}>{pc.ip}</span>
                      {r && (
                        <>
                          <span style={{ fontFamily: "var(--font-data)", fontSize: 10, color: "var(--text-3)" }}>
                            {r.latency}ms
                          </span>
                          <span style={{ fontFamily: "var(--font-data)", fontSize: 10, color: "var(--text-3)" }}>
                            {r.region}
                          </span>
                          <span style={{ fontFamily: "var(--font-data)", fontSize: 10, color: "var(--green)" }}>
                            score: {r.score}
                          </span>
                        </>
                      )}
                    </div>
                    <button
                      className="btn btn-primary btn-sm"
                      style={copiedIdx === idx ? { borderColor: "var(--green)", color: "var(--green)" } : { borderColor: "var(--cyan)", color: "var(--cyan)", background: "rgba(0,229,255,0.1)" }}
                      onClick={() => copyToClipboard(pc.config, idx)}
                    >
                      {copiedIdx === idx ? "✓ COPIED!" : (
                        <>
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" width="11" height="11">
                            <rect x="9" y="9" width="13" height="13" rx="2" />
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                          </svg>
                          COPY CONFIG
                        </>
                      )}
                    </button>
                  </div>
                  <div style={{
                    background: "#0a0a0a", borderRadius: 4, padding: "10px 14px",
                    border: "1px solid var(--border-dim)", fontFamily: "var(--font-data)",
                    fontSize: 10, color: "var(--text-2)", wordBreak: "break-all",
                    lineHeight: 1.6, maxHeight: 80, overflow: "hidden",
                    position: "relative"
                  }}>
                    {pc.config}
                    <div style={{
                      position: "absolute", bottom: 0, left: 0, right: 0, height: 24,
                      background: "linear-gradient(to top, #0a0a0a, transparent)"
                    }} />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Copy all */}
          {patchedConfigs.length > 1 && (
            <div style={{ marginTop: 14 }}>
              <button className="btn btn-secondary"
                onClick={() => copyToClipboard(patchedConfigs.map(p => p.config).join("\n"), -1)}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" width="11" height="11">
                  <rect x="9" y="9" width="13" height="13" rx="2" />
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                </svg>
                {copiedIdx === -1 ? "✓ ALL COPIED!" : `COPY ALL ${patchedConfigs.length} CONFIGS`}
              </button>
            </div>
          )}

          {/* Tips */}
          <div className="card" style={{ marginTop: 14, borderColor: "var(--border-dim)" }}>
            <div className="card-title">IMPORT TIPS</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {[
                { app: "v2rayNG (Android)", tip: "Long press → Import from clipboard" },
                { app: "Shadowrocket (iOS)", tip: "Scan QR or paste in Add Server" },
                { app: "v2rayN (Windows)", tip: "Servers → Import from clipboard" },
                { app: "Clash / Mihomo", tip: "Convert using sub-store or manually" },
                { app: "Hiddify", tip: "Add profile → paste config URL" },
                { app: "Streisand", tip: "Import via QR code or URI" },
              ].map(t => (
                <div key={t.app} style={{ display: "flex", gap: 10 }}>
                  <span style={{ color: "var(--cyan)", fontFamily: "var(--font-data)", fontSize: 10, minWidth: 140 }}>{t.app}</span>
                  <span style={{ color: "var(--text-3)", fontFamily: "var(--font-ui)", fontSize: 11 }}>{t.tip}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
