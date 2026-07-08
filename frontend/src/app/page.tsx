"use client";

import { useState, useEffect, useRef } from "react";
import { Shield, Server, Activity, AlertTriangle, CheckCircle, Database, ChevronDown, ChevronUp, FileText, Sliders } from "lucide-react";

const getBackendUrl = () => {
  if (typeof window !== "undefined") {
    if (window.location.port === "3000") {
      return "http://localhost:8080";
    }
    return `${window.location.protocol}//${window.location.host}`;
  }
  return "http://localhost:8080";
};

const getWebSocketUrl = (scanId: string | number) => {
  if (typeof window !== "undefined") {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    if (window.location.port === "3000") {
      return `ws://localhost:8080/api/ws/scan/${scanId}`;
    }
    return `${proto}//${window.location.host}/api/ws/scan/${scanId}`;
  }
  return `ws://localhost:8080/api/ws/scan/${scanId}`;
};

export default function Home() {
  const [target, setTarget] = useState("");
  const [scanStatus, setScanStatus] = useState("idle"); // idle, scanning, error, completed
  const [events, setEvents] = useState<any[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [models, setModels] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState("deepseek-coder:latest");
  const [diagnostics, setDiagnostics] = useState<any>({});
  const [bootstrapStatus, setBootstrapStatus] = useState("idle"); // idle, loading, completed, error
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState("console"); // console, vulns, ports

  // Advanced Scan settings
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [ports, setPorts] = useState("common");
  const [customPorts, setCustomPorts] = useState("");
  const [speed, setSpeed] = useState("T3");
  const [depth, setDepth] = useState("fast");
  const [customTemplate, setCustomTemplate] = useState("");
  const [templates, setTemplates] = useState<any[]>([]);
  const [proxy, setProxy] = useState("");
  const [userAgent, setUserAgent] = useState("");
  const [rateLimit, setRateLimit] = useState(0);

  // Template Composer settings
  const [activeSidebarTab, setActiveSidebarTab] = useState("controls"); // controls, composer
  const [composerName, setComposerName] = useState("custom-http-detect.yaml");
  const [composerYAML, setComposerYAML] = useState(`id: custom-http-detect
info:
  name: Custom HTTP Security Signature Detection
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200`);
  const [composerStatus, setComposerStatus] = useState("idle"); // idle, validating, saving, valid, invalid, saved
  const [composerError, setComposerError] = useState("");
  const [resetStatus, setResetStatus] = useState("idle"); // idle, resetting, done, error

  const wsRef = useRef<WebSocket | null>(null);

  const resetWorkspace = async () => {
    if (!confirm("Are you sure you want to completely uninstall local binaries, cached templates, and databases?")) {
      return;
    }
    setResetStatus("resetting");
    try {
      const res = await fetch(`${getBackendUrl()}/api/reset`, {
        method: "POST",
      });
      if (res.ok) {
        setResetStatus("done");
        fetchDiagnostics();
        fetchTemplates();
        setTimeout(() => setResetStatus("idle"), 3000);
      } else {
        setResetStatus("error");
      }
    } catch (e) {
      setResetStatus("error");
    }
  };

  useEffect(() => {
    fetchHistory();
    fetchModels();
    fetchDiagnostics();
    fetchTemplates();

    const interval = setInterval(() => {
      fetchDiagnostics();
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  const fetchTemplates = async () => {
    try {
      const res = await fetch(`${getBackendUrl()}/api/templates`);
      if (res.ok) {
        const data = await res.json();
        setTemplates(data || []);
      }
    } catch (e) {
      console.error("Failed to load templates:", e);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await fetch(`${getBackendUrl()}/api/scans`);
      if (res.ok) {
        setHistory(await res.json() || []);
      }
    } catch (e) {
      console.error("Failed to fetch history");
    }
  };

  const fetchModels = async () => {
    try {
      const res = await fetch(`${getBackendUrl()}/api/models`);
      if (res.ok) {
        const data = await res.json();
        setModels(data || []);
        if (data && data.length > 0) {
          if (data.includes("deepseek-coder:latest")) {
            setSelectedModel("deepseek-coder:latest");
          } else {
            setSelectedModel(data[0]);
          }
        }
      }
    } catch (e) {
      console.error("Failed to fetch models");
    }
  };

  const fetchDiagnostics = async () => {
    try {
      const res = await fetch(`${getBackendUrl()}/api/diagnostics`);
      if (res.ok) {
        setDiagnostics(await res.json() || {});
      }
    } catch (e) {
      console.error("Failed to fetch diagnostics");
    }
  };

  const bootstrapTools = async () => {
    setBootstrapStatus("loading");
    try {
      const res = await fetch(`${getBackendUrl()}/api/setup`, {
        method: "POST",
      });
      if (res.ok) {
        setBootstrapStatus("completed");
        fetchDiagnostics(); // refresh tools checklist!
      } else {
        setBootstrapStatus("error");
      }
    } catch (e) {
      setBootstrapStatus("error");
    }
  };

  const loadScanDetails = async (scanId: number) => {
    setScanStatus("completed");
    setSelectedScanId(scanId);
    setEvents([]);
    try {
      const res = await fetch(`${getBackendUrl()}/api/scan/${scanId}`);
      if (res.ok) {
        const data = await res.json();
        const simulatedEvents: any[] = [];
        if (data.subdomains) {
          data.subdomains.forEach((sub: string) => {
            simulatedEvents.push({ type: "subdomain", data: sub });
          });
        }
        if (data.nmap_scan) {
          simulatedEvents.push({ type: "nmap", data: data.nmap_scan });
        }
        if (data.technologies) {
          simulatedEvents.push({ type: "technology", data: data.technologies });
        }
        if (data.nuclei_findings) {
          data.nuclei_findings.forEach((find: any) => {
            simulatedEvents.push({ type: "nuclei", data: find });
          });
        }
        if (data.ai_suggestions) {
          simulatedEvents.push({ type: "info", message: "AI Review Analysis:\n" + data.ai_suggestions });
        }
        setEvents(simulatedEvents);
      }
    } catch (e) {
      console.error("Failed to load scan details:", e);
    }
  };

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;

    setScanStatus("scanning");
    setEvents([]);
    setSelectedScanId(null);

    try {
      const res = await fetch(`${getBackendUrl()}/api/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target,
          model: selectedModel,
          ports: ports === "custom" ? customPorts : ports,
          speed,
          depth,
          custom_template: customTemplate,
          proxy,
          user_agent: userAgent,
          rate_limit: rateLimit,
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(errText || "Server error starting scan");
      }
      const data = await res.json();
      connectWebSocket(data.scan_id);
    } catch (err) {
      setScanStatus("error");
      setEvents((prev) => [...prev, { type: "error", message: "Failed to start scan" }]);
    }
  };

  const connectWebSocket = (scanId: string) => {
    if (wsRef.current) wsRef.current.close();

    const ws = new WebSocket(getWebSocketUrl(scanId));
    wsRef.current = ws;

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setEvents((prev) => [...prev, data]);
      if (data.type === "done") {
        setScanStatus("completed");
        ws.close();
        fetchHistory();
      }
      if (data.type === "error") {
        setScanStatus("error");
        ws.close();
      }
    };

    ws.onerror = () => {
      setScanStatus("error");
      setEvents((prev) => [...prev, { type: "error", message: "WebSocket connection error" }]);
    };
  };

  const validateTemplate = async () => {
    setComposerStatus("validating");
    setComposerError("");
    try {
      const res = await fetch(`${getBackendUrl()}/api/templates/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yaml: composerYAML }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.valid) {
          setComposerStatus("valid");
        } else {
          setComposerStatus("invalid");
          setComposerError(data.error);
        }
      } else {
        setComposerStatus("invalid");
        setComposerError("HTTP error validating template");
      }
    } catch (e: any) {
      setComposerStatus("invalid");
      setComposerError(e.message || "Failed to communicate with validator");
    }
  };

  const saveTemplate = async () => {
    if (!composerName) {
      setComposerStatus("invalid");
      setComposerError("Please specify a template filename (e.g. sql-check.yaml)");
      return;
    }
    setComposerStatus("saving");
    setComposerError("");
    try {
      const res = await fetch(`${getBackendUrl()}/api/templates/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: composerName, yaml: composerYAML }),
      });
      if (res.ok) {
        setComposerStatus("saved");
        fetchTemplates();
      } else {
        const errText = await res.text();
        setComposerStatus("invalid");
        setComposerError(errText || "HTTP error saving template");
      }
    } catch (e: any) {
      setComposerStatus("invalid");
      setComposerError(e.message || "Failed to save template");
    }
  };

  const renderEventData = (event: any) => {
    switch (event.type) {
      case "subdomain":
        return <div className="text-blue-400 font-mono pl-4">└── {event.data}</div>;
      case "nmap":
        return <pre className="text-gray-400 text-xs overflow-x-auto p-2 bg-black/50 rounded mt-1">{event.data}</pre>;
      case "nuclei":
        return (
          <div className="bg-red-500/10 border border-red-500/50 rounded p-2 mt-1">
            <span className="text-red-400 font-bold">[{event.data.info?.severity?.toUpperCase() || "VULN"}]</span>
            <span className="text-white ml-2">{event.data.info?.name}</span>
          </div>
        );
      case "leak":
        return (
          <div className="bg-orange-500/10 border border-orange-500/50 rounded p-3 mt-1 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-orange-500/20 pb-1 mb-2">
              <span className="text-orange-400 font-bold">[{event.data.severity}] NATIVE LEAK: {event.data.type}</span>
              <span className="text-neutral-500">{event.data.path}</span>
            </div>
            <div className="text-neutral-300 mb-2">{event.data.description}</div>
            {event.data.evidence && (
              <pre className="bg-black/80 text-green-400 p-2.5 rounded border border-white/5 overflow-x-auto max-h-32 text-[10px] whitespace-pre-wrap">{event.data.evidence}</pre>
            )}
          </div>
        );
      case "cve":
        return (
          <div className="bg-purple-500/10 border border-purple-500/50 rounded p-3 mt-1 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-purple-500/20 pb-1 mb-2">
              <span className="text-purple-400 font-bold">[📊 MITRE CORRELATED] {event.data.id}: {event.data.name}</span>
              <span className="text-neutral-500">CVSS {event.data.cvss} | EPSS {(event.data.epss * 100).toFixed(0)}%</span>
            </div>
            <div className="text-neutral-300">{event.data.description}</div>
            <div className="text-[10px] text-purple-300/80 mt-1">
              Tactic: {event.data.mitre_tactic} | Technique: {event.data.mitre_technique}
            </div>
          </div>
        );
      case "kev":
        return (
          <div className="bg-red-500/10 border border-red-500/60 rounded p-3 mt-1 font-mono text-xs animate-pulse">
            <div className="flex items-center justify-between border-b border-red-500/20 pb-1 mb-2">
              <span className="text-red-400 font-bold">🚨 [CISA KEV ALERT] {event.data.cve_id}</span>
              <span className="text-neutral-500">Actively Exploited</span>
            </div>
            <div className="text-white font-bold mb-1">{event.data.vulnerability_name}</div>
            <div className="text-neutral-300 mb-2">{event.data.description}</div>
            <div className="text-red-400 font-bold text-[10px]">Action Required: {event.data.required_action}</div>
          </div>
        );
      case "technology":
        return <div className="text-green-400 font-mono text-xs mt-1">{JSON.stringify(event.data)}</div>;
      case "info":
      default:
        return <div className="text-gray-300">{event.message}</div>;
    }
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-white font-sans selection:bg-indigo-500/30">
      {/* Top Navbar */}
      <nav className="border-b border-white/10 bg-black/20 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-indigo-500" />
            <span className="text-xl font-bold bg-gradient-to-r from-indigo-400 to-cyan-400 bg-clip-text text-transparent">
              VulnSightAI v2
            </span>
            <span className="text-xs px-2 py-0.5 rounded-full border border-indigo-500/30 text-indigo-400 bg-indigo-500/10 ml-2">Miltary Grade</span>
          </div>
          {/* Diagnostics Indicators */}
          <div className="hidden md:flex items-center gap-3 text-xs bg-neutral-900 border border-white/5 py-1.5 px-3.5 rounded-full font-mono">
            <span className="text-neutral-500 mr-1 select-none text-[10px] uppercase font-bold tracking-wider">SYSTEMS:</span>
            {Object.keys(diagnostics).length === 0 ? (
              <span className="text-neutral-500 animate-pulse text-[10px]">Running checks...</span>
            ) : (
              Object.entries(diagnostics).map(([tool, ok]) => (
                <div key={tool} className="flex items-center gap-1.5">
                  <span className={`w-1.5 h-1.5 rounded-full ${ok ? "bg-green-500" : "bg-neutral-600"}`}></span>
                  <span className={ok ? "text-neutral-300" : "text-neutral-500 line-through"}>{tool}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-8 grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column - Controls & History */}
        <div className="lg:col-span-4 space-y-6">
          {/* Sidebar Tab Switcher */}
          <div className="flex bg-neutral-900 border border-white/5 rounded-xl p-1 gap-1">
            <button
              onClick={() => setActiveSidebarTab("controls")}
              className={`flex-1 py-2 rounded-lg text-xs font-bold font-mono transition-all flex items-center justify-center gap-1.5 cursor-pointer ${
                activeSidebarTab === "controls" ? "bg-indigo-600 text-white" : "text-neutral-500 hover:text-neutral-300"
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              Scanner
            </button>
            <button
              onClick={() => setActiveSidebarTab("composer")}
              className={`flex-1 py-2 rounded-lg text-xs font-bold font-mono transition-all flex items-center justify-center gap-1.5 cursor-pointer ${
                activeSidebarTab === "composer" ? "bg-indigo-600 text-white" : "text-neutral-500 hover:text-neutral-300"
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              Composer
            </button>
          </div>

          {activeSidebarTab === "controls" ? (
            <>
              {/* Scan Control Panel */}
              <div className="bg-neutral-900 border border-white/10 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-indigo-500 via-cyan-400 to-indigo-500"></div>
                
                <h2 className="text-lg font-semibold flex items-center gap-2 mb-4">
                  <Activity className="w-5 h-5 text-indigo-400" />
                  New Operation
                </h2>
                
                <form onSubmit={startScan} className="space-y-4">
                  <div>
                    <label className="text-xs text-neutral-400 uppercase tracking-wider font-semibold mb-2 block">Target Asset (Domain/IP)</label>
                    <div className="relative">
                      <Server className="w-5 h-5 absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
                      <input
                        type="text"
                        required
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        placeholder="example.com"
                        className="w-full bg-black/50 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all placeholder:text-neutral-600 font-mono"
                        disabled={scanStatus === "scanning"}
                      />
                    </div>
                  </div>
                  
                  <div>
                    <label className="text-xs text-neutral-400 uppercase tracking-wider font-semibold mb-2 block">AI Reviewer Model</label>
                    <select
                      value={selectedModel}
                      onChange={(e) => setSelectedModel(e.target.value)}
                      disabled={scanStatus === "scanning"}
                      className="w-full bg-black/50 border border-white/10 rounded-xl py-3 px-3 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono text-sm"
                    >
                      {models.length === 0 ? (
                        <option value="deepseek-coder:latest">deepseek-coder:latest (offline)</option>
                      ) : (
                        models.map((m) => (
                          <option key={m} value={m}>{m}</option>
                        ))
                      )}
                    </select>
                  </div>

                  {/* Collapsible Advanced settings */}
                  <div className="border-t border-white/5 pt-3">
                    <button
                      type="button"
                      onClick={() => setShowAdvanced(!showAdvanced)}
                      className="flex items-center justify-between w-full text-xs text-neutral-400 hover:text-white transition-colors py-1 cursor-pointer"
                    >
                      <span className="font-semibold uppercase tracking-wider">Advanced Scan Modifiers</span>
                      {showAdvanced ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>

                    {showAdvanced && (
                      <div className="mt-3 space-y-3 animate-in fade-in slide-in-from-top-1 duration-200">
                        {/* Target Ports Selection */}
                        <div>
                          <label className="text-[10px] text-neutral-400 uppercase font-semibold mb-1 block">Scan Ports</label>
                          <select
                            value={ports}
                            onChange={(e) => setPorts(e.target.value)}
                            className="w-full bg-black/50 border border-white/10 rounded-lg py-2 px-3 text-xs text-white focus:outline-none focus:border-indigo-500 transition-all font-mono"
                          >
                            <option value="common">Common Ports (Top 100)</option>
                            <option value="all">All Ports (1-65535)</option>
                            <option value="custom">Custom Port Range...</option>
                          </select>
                          {ports === "custom" && (
                            <input
                              type="text"
                              required
                              value={customPorts}
                              onChange={(e) => setCustomPorts(e.target.value)}
                              placeholder="e.g. 80,443,8080"
                              className="mt-1.5 w-full bg-black/50 border border-white/10 rounded-lg py-2 px-3 text-xs text-white focus:outline-none focus:border-indigo-500 transition-all font-mono"
                            />
                          )}
                        </div>

                        {/* Scan Speed Modifier */}
                        <div>
                          <label className="text-[10px] text-neutral-400 uppercase font-semibold mb-1 block">Scan speed (Stealth / Aggressive)</label>
                          <select
                            value={speed}
                            onChange={(e) => setSpeed(e.target.value)}
                            className="w-full bg-black/50 border border-white/10 rounded-lg py-2 px-3 text-xs text-white focus:outline-none focus:border-indigo-500 transition-all font-mono"
                          >
                            <option value="T1">T1 (Paranoid - Ultra Stealth)</option>
                            <option value="T2">T2 (Sneaky)</option>
                            <option value="T3">T3 (Normal Speed)</option>
                            <option value="T4">T4 (Aggressive Scan)</option>
                            <option value="T5">T5 (Insane Speed)</option>
                          </select>
                        </div>

                        {/* Scan Depth Selection */}
                        <div>
                          <label className="text-[10px] text-neutral-400 uppercase font-semibold mb-1 block">Bruteforce Scan Depth</label>
                          <select
                            value={depth}
                            onChange={(e) => setDepth(e.target.value)}
                            className="w-full bg-black/50 border border-white/10 rounded-lg py-2 px-3 text-xs text-white focus:outline-none focus:border-indigo-500 transition-all font-mono"
                          >
                            <option value="fast">Fast (Standard Discovery)</option>
                            <option value="deep">Deep (Brute Force All Namespaces)</option>
                          </select>
                        </div>

                        {/* Custom Template Selection */}
                        <div>
                          <label className="text-[10px] text-neutral-400 uppercase font-semibold mb-1 block">Nuclei Custom Template</label>
                          <select
                            value={customTemplate}
                            onChange={(e) => setCustomTemplate(e.target.value)}
                            className="w-full bg-black/50 border border-white/10 rounded-lg py-2 px-3 text-xs text-white focus:outline-none focus:border-indigo-500 transition-all font-mono"
                          >
                            <option value="">None (Run Default Scans)</option>
                            {templates.map((t) => (
                              <option key={t.name} value={t.name}>
                                {t.name} ({t.id})
                              </option>
                            ))}
                          </select>
                        </div>

                        {/* Proxy Routing Configuration */}
                        <div>
                          <label className="text-[10px] text-neutral-400 uppercase font-semibold mb-1 block">Network Proxy Server</label>
                          <input
                            type="text"
                            value={proxy}
                            onChange={(e) => setProxy(e.target.value)}
                            placeholder="e.g. socks5://127.0.0.1:9050"
                            className="w-full bg-black/50 border border-white/10 rounded-lg py-2 px-3 text-xs text-white focus:outline-none focus:border-indigo-500 transition-all font-mono"
                          />
                        </div>

                        {/* Custom User-Agent Header */}
                        <div>
                          <label className="text-[10px] text-neutral-400 uppercase font-semibold mb-1 block">Custom HTTP User-Agent</label>
                          <input
                            type="text"
                            value={userAgent}
                            onChange={(e) => setUserAgent(e.target.value)}
                            placeholder="e.g. Mozilla/5.0 (Windows NT 10.0...)"
                            className="w-full bg-black/50 border border-white/10 rounded-lg py-2 px-3 text-xs text-white focus:outline-none focus:border-indigo-500 transition-all font-mono"
                          />
                        </div>

                        {/* Request Rate Limiting (RPS) */}
                        <div>
                          <label className="text-[10px] text-neutral-400 uppercase font-semibold mb-1 block">Request Rate Limit (RPS)</label>
                          <input
                            type="number"
                            min="0"
                            value={rateLimit || ""}
                            onChange={(e) => setRateLimit(parseInt(e.target.value) || 0)}
                            placeholder="0 (Unlimited)"
                            className="w-full bg-black/50 border border-white/10 rounded-lg py-2 px-3 text-xs text-white focus:outline-none focus:border-indigo-500 transition-all font-mono"
                          />
                        </div>
                      </div>
                    )}
                  </div>
                  
                  <button
                    type="submit"
                    disabled={scanStatus === "scanning"}
                    className={`w-full py-3 rounded-xl font-bold flex items-center justify-center gap-2 transition-all cursor-pointer ${
                      scanStatus === "scanning" 
                        ? "bg-indigo-500/50 text-indigo-200 cursor-not-allowed animate-pulse" 
                        : "bg-indigo-600 hover:bg-indigo-500 hover:shadow-[0_0_20px_rgba(99,102,241,0.4)] text-white"
                    }`}
                  >
                    {scanStatus === "scanning" ? (
                      <>Initializing Matrix...</>
                    ) : (
                      <>Engage Scan</>
                    )}
                  </button>
                </form>
              </div>

              {/* Telemetry Analytics Panel */}
              <div className="bg-neutral-900 border border-white/10 rounded-2xl p-6 relative overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-500 to-indigo-500"></div>
                <h2 className="text-lg font-semibold flex items-center gap-2 mb-4">
                  <Activity className="w-5 h-5 text-indigo-400" />
                  Telemetry Analytics
                </h2>
                
                <div className="grid grid-cols-2 gap-4 items-center">
                  {/* Circular Gauge */}
                  <div className="flex flex-col items-center justify-center p-3 bg-black/30 border border-white/5 rounded-xl">
                    <div className="relative w-20 h-20">
                      {/* Outer circle track */}
                      <svg className="w-full h-full transform -rotate-90">
                        <circle
                          cx="40"
                          cy="40"
                          r="32"
                          className="stroke-neutral-800"
                          strokeWidth="5"
                          fill="transparent"
                        />
                        <circle
                          cx="40"
                          cy="40"
                          r="32"
                          className="stroke-indigo-500 transition-all duration-500"
                          strokeWidth="5"
                          fill="transparent"
                          strokeDasharray={`${2 * Math.PI * 32}`}
                          strokeDashoffset={`${2 * Math.PI * 32 * (1 - (Object.values(diagnostics).filter(Boolean).length / (Object.keys(diagnostics).length || 5)))}`}
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-sm font-mono font-bold">
                          {Math.round((Object.values(diagnostics).filter(Boolean).length / (Object.keys(diagnostics).length || 5)) * 100)}%
                        </span>
                        <span className="text-[7px] text-neutral-500 uppercase tracking-widest font-bold">Integrity</span>
                      </div>
                    </div>
                  </div>

                  {/* Stats Column */}
                  <div className="space-y-2">
                    <div className="bg-black/30 border border-white/5 p-2 rounded-xl">
                      <div className="text-[10px] text-neutral-400">Total Scans</div>
                      <div className="text-md font-mono font-bold text-white">{history.length}</div>
                    </div>
                    <div className="bg-black/30 border border-white/5 p-2 rounded-xl">
                      <div className="text-[10px] text-neutral-400">Unique Targets</div>
                      <div className="text-md font-mono font-bold text-indigo-300">
                        {new Set(history.map((h: any) => h.target)).size}
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Visual Bar Breakdown */}
                <div className="mt-4 pt-4 border-t border-white/5">
                  <div className="text-[10px] text-neutral-400 mb-2 font-semibold uppercase tracking-wider">Tool Deployment Status</div>
                  <div className="space-y-1.5 font-mono text-xs">
                    {Object.entries(diagnostics).map(([tool, ok]) => (
                      <div key={tool} className="flex items-center justify-between">
                        <span className="text-neutral-400 capitalize text-[10px]">{tool}</span>
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1 bg-neutral-800 rounded-full overflow-hidden">
                            <div className={`h-full rounded-full transition-all ${ok ? "w-full bg-green-500" : "w-0 bg-neutral-600"}`}></div>
                          </div>
                          <span className={`text-[10px] ${ok ? "text-green-400" : "text-neutral-500"}`}>{ok ? "Online" : "Offline"}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Bootstrap Button */}
                <div className="mt-4">
                  <button
                    onClick={bootstrapTools}
                    disabled={bootstrapStatus === "loading"}
                    className={`w-full py-2 rounded-xl text-xs font-bold transition-all border cursor-pointer ${
                      bootstrapStatus === "loading"
                        ? "bg-indigo-500/10 border-indigo-500/30 text-indigo-400 cursor-not-allowed animate-pulse"
                        : "bg-indigo-600/10 border-indigo-500/30 text-indigo-400 hover:bg-indigo-500 hover:text-white hover:shadow-[0_0_15px_rgba(99,102,241,0.3)]"
                    }`}
                  >
                    {bootstrapStatus === "loading" ? "Bootstrapping Framework..." : "Install Missing Tools"}
                  </button>
                  <button
                    onClick={resetWorkspace}
                    disabled={resetStatus === "resetting"}
                    className={`w-full mt-2 py-2 rounded-xl text-xs font-bold transition-all border cursor-pointer ${
                      resetStatus === "resetting"
                        ? "bg-red-500/10 border-red-500/30 text-red-400 cursor-not-allowed animate-pulse"
                        : "bg-red-600/10 border-red-500/30 text-red-400 hover:bg-red-600 hover:text-white hover:shadow-[0_0_15px_rgba(239,68,68,0.3)]"
                    }`}
                  >
                    {resetStatus === "resetting" ? "Resetting Workspace..." : "Reset / Clean Workspace"}
                  </button>
                </div>
              </div>
            </>
          ) : (
            /* Template Composer Tab View */
            <div className="bg-neutral-900 border border-white/10 rounded-2xl p-6 shadow-2xl space-y-4 animate-in fade-in duration-200">
              <h2 className="text-lg font-semibold flex items-center gap-2 border-b border-white/5 pb-2">
                <FileText className="w-5 h-5 text-indigo-400" />
                Template Composer
              </h2>

              <div>
                <label className="text-[10px] text-neutral-400 uppercase tracking-wider font-semibold mb-1 block">Template Filename</label>
                <input
                  type="text"
                  value={composerName}
                  onChange={(e) => setComposerName(e.target.value)}
                  placeholder="custom-detect.yaml"
                  className="w-full bg-black/50 border border-white/10 rounded-xl py-2 px-3 text-xs text-white focus:outline-none focus:border-indigo-500 font-mono"
                />
              </div>

              <div>
                <label className="text-[10px] text-neutral-400 uppercase tracking-wider font-semibold mb-1 block">Nuclei YAML Signature Code</label>
                <textarea
                  value={composerYAML}
                  onChange={(e) => setComposerYAML(e.target.value)}
                  className="w-full h-64 bg-black/50 border border-white/10 rounded-xl p-3 text-xs text-indigo-300 focus:outline-none focus:border-indigo-500 font-mono resize-none"
                  spellCheck={false}
                />
              </div>

              {/* Validator status block */}
              {composerStatus !== "idle" && (
                <div className={`p-3 rounded-xl border text-xs font-mono ${
                  composerStatus === "validating" ? "bg-indigo-500/10 border-indigo-500/30 text-indigo-400 animate-pulse" :
                  composerStatus === "saving" ? "bg-indigo-500/10 border-indigo-500/30 text-indigo-400" :
                  composerStatus === "valid" ? "bg-green-500/10 border-green-500/30 text-green-400" :
                  composerStatus === "saved" ? "bg-green-500/10 border-green-500/30 text-green-400" :
                  "bg-red-500/10 border-red-500/30 text-red-400"
                }`}>
                  {composerStatus === "validating" && "⏳ Validating template schema syntax..."}
                  {composerStatus === "saving" && "💾 Storing custom template on disk..."}
                  {composerStatus === "valid" && "✓ Template schema is structurally valid!"}
                  {composerStatus === "saved" && "✓ Custom template successfully compiled and saved!"}
                  {composerStatus === "invalid" && `✗ Schema error: ${composerError}`}
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex gap-2">
                <button
                  onClick={validateTemplate}
                  disabled={composerStatus === "validating" || composerStatus === "saving"}
                  className="flex-1 py-2.5 bg-neutral-800 hover:bg-neutral-700 text-white rounded-xl text-xs font-bold transition-all border border-white/5 cursor-pointer"
                >
                  Validate Schema
                </button>
                <button
                  onClick={saveTemplate}
                  disabled={composerStatus === "validating" || composerStatus === "saving"}
                  className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-bold transition-all cursor-pointer"
                >
                  Save Template
                </button>
              </div>

              {/* Loaded custom templates checklist */}
              <div className="border-t border-white/5 pt-3">
                <label className="text-[10px] text-neutral-400 uppercase tracking-wider font-semibold mb-2 block">Saved Custom Signatures</label>
                {templates.length === 0 ? (
                  <p className="text-[10px] text-neutral-500 font-mono">No custom signatures loaded.</p>
                ) : (
                  <div className="space-y-1.5 max-h-[150px] overflow-y-auto pr-1 custom-scrollbar">
                    {templates.map((t) => (
                      <div key={t.name} className="flex justify-between items-center bg-black/40 border border-white/5 p-2 rounded-lg text-[10px]">
                        <div className="flex flex-col truncate pr-2">
                          <span className="font-mono text-indigo-300 font-bold truncate">{t.name}</span>
                          <span className="text-neutral-500 truncate">{t.title}</span>
                        </div>
                        <button
                          onClick={() => {
                            setCustomTemplate(t.name);
                            setShowAdvanced(true);
                            setPorts("common");
                            setActiveSidebarTab("controls");
                          }}
                          className="px-2 py-1 bg-indigo-600/20 hover:bg-indigo-600 hover:text-white text-indigo-400 rounded transition-all font-mono font-bold cursor-pointer"
                        >
                          Select
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* History Panel */}
          <div className="bg-neutral-900 border border-white/10 rounded-2xl p-6">
             <h2 className="text-lg font-semibold flex items-center gap-2 mb-4">
              <Database className="w-5 h-5 text-indigo-400" />
              Archived Operations
            </h2>
            
            <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
              {history.length === 0 ? (
                <p className="text-sm text-neutral-500 text-center py-4">No past operations found.</p>
              ) : (
                history.map((item, idx) => (
                  <div
                    key={idx}
                    onClick={() => loadScanDetails(item.id)}
                    className={`border p-3 rounded-xl hover:bg-white/5 transition-colors cursor-pointer group ${
                      selectedScanId === item.id ? "border-indigo-500 bg-indigo-500/5" : "border-white/5 bg-black/40"
                    }`}
                  >
                    <div className="flex justify-between items-start mb-1">
                      <span className="font-mono text-sm text-indigo-300 group-hover:text-indigo-200">{item.target}</span>
                      <span className="text-[10px] text-neutral-500">{item.timestamp}</span>
                    </div>
                    <a
                      href={`${getBackendUrl()}/api/report/${item.id}`}
                      onClick={(e) => e.stopPropagation()} // prevent loading scan details on download click
                      className="mt-2 text-xs text-center block w-full bg-white/5 hover:bg-white/10 text-white rounded py-1 border border-white/10 transition-all"
                    >
                      Download HTML Report
                    </a>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Column - Live Stream */}
        <div className="lg:col-span-8 flex flex-col">
          <div className="bg-black rounded-2xl border border-neutral-800 flex-1 min-h-[600px] relative overflow-hidden flex flex-col shadow-2xl">
            {/* Terminal Header with tabs */}
            <div className="bg-neutral-900/80 border-b border-neutral-800 h-12 flex items-center px-4 justify-between shrink-0">
              <div className="flex gap-2 items-center">
                <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
              </div>
              
              {/* Dynamic Tabs */}
              <div className="flex gap-2 font-mono text-xs border-l border-neutral-800 pl-4 h-full items-center">
                <button
                  onClick={() => setActiveTab("console")}
                  className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                    activeTab === "console"
                      ? "bg-indigo-600 text-white font-bold"
                      : "text-neutral-500 hover:text-neutral-300"
                  }`}
                >
                  Console Logs
                </button>
                <button
                  onClick={() => setActiveTab("vulns")}
                  className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                    activeTab === "vulns"
                      ? "bg-indigo-600 text-white font-bold"
                      : "text-neutral-500 hover:text-neutral-300"
                  }`}
                >
                  Threat Index ({events.filter(e => e.type === "nuclei").length})
                </button>
                <button
                  onClick={() => setActiveTab("ports")}
                  className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                    activeTab === "ports"
                      ? "bg-indigo-600 text-white font-bold"
                      : "text-neutral-500 hover:text-neutral-300"
                  }`}
                >
                  Network Footprint
                </button>
                <button
                  onClick={() => setActiveTab("visualizer")}
                  className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                    activeTab === "visualizer"
                      ? "bg-indigo-600 text-white font-bold"
                      : "text-neutral-500 hover:text-neutral-300"
                  }`}
                >
                  Network Visualizer
                </button>
                <button
                  onClick={() => setActiveTab("mitre")}
                  className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                    activeTab === "mitre"
                      ? "bg-indigo-600 text-white font-bold"
                      : "text-neutral-500 hover:text-neutral-300"
                  }`}
                >
                  MITRE ATT&CK
                </button>
              </div>
            </div>
            
            {/* Terminal Body */}
            <div className="p-4 overflow-y-auto flex-1 font-mono text-sm space-y-2">
              {events.length === 0 && scanStatus !== "scanning" ? (
                <div className="h-full flex flex-col items-center justify-center text-neutral-600 gap-4 opacity-50">
                  <Shield className="w-16 h-16" />
                  <p>Awaiting Command</p>
                </div>
              ) : activeTab === "console" ? (
                /* Console Logs Tab */
                events.map((ev, i) => (
                  <div key={i} className="animate-in fade-in slide-in-from-bottom-2 duration-300">
                    <div className="flex items-start gap-2">
                      <span className="text-neutral-500 shrink-0 select-none">[{new Date().toLocaleTimeString()}]</span>
                      <div className="flex-1">
                        {renderEventData(ev)}
                      </div>
                    </div>
                  </div>
                ))
              ) : activeTab === "vulns" ? (
                /* Structured Vulnerability Index Tab */
                (events.filter(e => e.type === "nuclei").map(e => e.data).length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-neutral-600 py-12 gap-2 opacity-50">
                    <CheckCircle className="w-12 h-12 text-green-500/80 animate-pulse" />
                    <p>No Vulnerabilities Discovered</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {events.filter(e => e.type === "nuclei").map(e => e.data).map((find: any, idx: number) => {
                      const severity = find.info?.severity?.toUpperCase() || "INFO";
                      const name = find.info?.name || "Detected threat";
                      const desc = find.info?.description || "No description provided.";
                      const url = find["matched-at"] || find.matched || "";
                      return (
                        <div key={idx} className="bg-neutral-900/60 border border-white/5 rounded-xl p-4 relative overflow-hidden">
                          {/* Border indicator */}
                          <div className={`absolute left-0 top-0 bottom-0 w-1 ${
                            severity === "CRITICAL" ? "bg-red-600" :
                            severity === "HIGH" ? "bg-orange-500" :
                            severity === "MEDIUM" ? "bg-yellow-500" :
                            severity === "LOW" ? "bg-blue-500" : "bg-neutral-500"
                          }`}></div>
                          <div className="flex justify-between items-start mb-2 pl-2">
                            <span className="text-white font-bold text-sm">{name}</span>
                            <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                              severity === "CRITICAL" ? "bg-red-500/10 text-red-400 border border-red-500/30" :
                              severity === "HIGH" ? "bg-orange-500/10 text-orange-400 border border-orange-500/30" :
                              severity === "MEDIUM" ? "bg-yellow-500/10 text-yellow-400 border border-yellow-500/30" :
                              severity === "LOW" ? "bg-blue-500/10 text-blue-400 border border-blue-500/30" :
                              "bg-neutral-500/10 text-neutral-400 border border-neutral-500/30"
                            }`}>{severity}</span>
                          </div>
                          <p className="text-xs text-neutral-400 pl-2 leading-relaxed">{desc}</p>
                          {url && (
                            <div className="mt-3 pl-2 text-xs">
                              <span className="text-neutral-500">Target URL: </span>
                              <a href={url} target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:underline break-all font-mono">{url}</a>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ))
              ) : activeTab === "ports" ? (
                /* Parsed Nmap Port Scan Tab */
                (() => {
                  const nmapEvent = events.find(e => e.type === "nmap");
                  const parseNmapOutput = (rawNmap: string) => {
                    const services: any[] = [];
                    const lines = rawNmap.split("\n");
                    const regex = /^(\d+\/\w+)\s+(\w+)\s+(\S+)\s*(.*)$/;
                    lines.forEach(line => {
                      const matches = line.trim().match(regex);
                      if (matches) {
                        services.push({
                          port: matches[1],
                          state: matches[2],
                          service: matches[3],
                          version: matches[4] || ""
                        });
                      }
                    });
                    return services;
                  };
                  const nmapServices = nmapEvent ? parseNmapOutput(nmapEvent.data) : [];

                  return nmapServices.length === 0 ? (
                    <div className="h-full flex flex-col items-center justify-center text-neutral-600 py-12 gap-2 opacity-50">
                      <Server className="w-12 h-12" />
                      <p>No Active Port Footprint</p>
                    </div>
                  ) : (
                    <div className="overflow-x-auto border border-white/5 rounded-xl bg-neutral-900/30">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead>
                          <tr className="border-b border-white/5 bg-black/40 text-neutral-400 font-bold uppercase tracking-wider text-[10px]">
                            <th className="p-4">Port / Protocol</th>
                            <th className="p-4">State</th>
                            <th className="p-4">Service</th>
                            <th className="p-4">Software Version</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5 font-mono">
                          {nmapServices.map((srv, idx) => (
                            <tr key={idx} className="hover:bg-white/5 transition-colors">
                              <td className="p-4 font-bold text-indigo-400">{srv.port}</td>
                              <td className="p-4">
                                <span className={`inline-flex items-center gap-1.5 font-bold ${
                                  srv.state === "open" ? "text-green-400" : "text-neutral-500"
                                }`}>
                                  {srv.state === "open" && <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span>}
                                  {srv.state}
                                </span>
                              </td>
                              <td className="p-4 text-neutral-300">{srv.service}</td>
                              <td className="p-4 text-neutral-500">{srv.version || "-"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  );
                })()
              ) : activeTab === "mitre" ? (
                <MitreAttackMatrix events={events} />
              ) : (
                /* Interactive Network Graph Visualizer Tab */
                <NetworkVisualizer events={events} target={target} />
              )}
 
              {scanStatus === "scanning" && (
                <div className="flex items-center gap-2 mt-4 text-indigo-400/80 animate-pulse">
                  <span className="w-2 h-4 bg-indigo-400 inline-block animate-ping"></span>
                  Processing stream...
                </div>
              )}
            </div>
          </div>
        </div>
      </main>

      <style dangerouslySetInnerHTML={{__html: `
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(0,0,0,0.2); border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
      `}} />
    </div>
  );
}

interface NetworkVisualizerProps {
  events: any[];
  target: string;
}

function NetworkVisualizer({ events, target }: NetworkVisualizerProps) {
  const [selectedNode, setSelectedNode] = useState<any>(null);

  // 1. Parse subdomains
  const subdomains = events
    .filter((e) => e.type === "subdomain")
    .map((e) => e.data);

  // 2. Parse ports
  const nmapEvent = events.find((e) => e.type === "nmap");
  const ports: any[] = [];
  if (nmapEvent && nmapEvent.data) {
    const lines = nmapEvent.data.split("\n");
    const regex = /^(\d+\/\w+)\s+(\w+)\s+(\S+)\s*(.*)$/;
    lines.forEach((line: string) => {
      const matches = line.trim().match(regex);
      if (matches) {
        ports.push({
          port: matches[1],
          service: matches[3],
          version: matches[4] || "",
        });
      }
    });
  }

  // 3. Parse vulnerabilities, native leaks, CVE correlations, & KEV alerts
  const vulns = events
    .filter((e) => e.type === "nuclei")
    .map((e) => e.data);

  const leaks = events
    .filter((e) => e.type === "leak")
    .map((e) => e.data);

  const cves = events
    .filter((e) => e.type === "cve")
    .map((e) => e.data);

  const kevs = events
    .filter((e) => e.type === "kev")
    .map((e) => e.data);

  const width = 1000;
  const height = 600;

  const nodes: any[] = [];
  const links: any[] = [];

  // Root Node
  const rootNode = {
    id: "root",
    label: target || "Target Domain",
    type: "root",
    x: 80,
    y: 300,
    color: "#4f46e5", // Indigo
    details: {
      type: "Primary Target Asset",
      address: target,
      subdomainsCount: subdomains.length,
      portsCount: ports.length,
      vulnsCount: vulns.length + leaks.length + cves.length,
    },
  };
  nodes.push(rootNode);

  // Subdomain Nodes
  const subYSpacing = Math.max(80, height / (subdomains.length + 1));
  subdomains.forEach((sub, idx) => {
    const y = subYSpacing * (idx + 1);
    const subNode = {
      id: `sub_${idx}`,
      label: sub,
      type: "subdomain",
      x: 340,
      y: y,
      color: "#06b6d4", // Cyan
      details: {
        type: "Discovered Subdomain Namespace",
        hostname: sub,
        index: idx + 1,
      },
    };
    nodes.push(subNode);
    links.push({ from: rootNode, to: subNode });
  });

  // Open Ports Nodes
  const portYSpacing = Math.max(80, height / (ports.length + 1));
  ports.forEach((p, idx) => {
    const y = portYSpacing * (idx + 1);
    const portNode = {
      id: `port_${idx}`,
      label: p.port,
      type: "port",
      x: 600,
      y: y,
      color: "#6366f1", // Neon Indigo
      details: {
        type: "Open Network Port",
        port: p.port,
        service: p.service,
        version: p.version || "Unknown Version",
      },
    };
    nodes.push(portNode);
    links.push({ from: rootNode, to: portNode });
  });

  // Threat Nodes (Combination of Nuclei Vulnerabilities, Native leaks, and CVE correlations)
  const threats = [
    ...vulns.map((v, idx) => ({
      id: `vuln_${idx}`,
      label: v.info?.name || "Threat",
      type: "vulnerability",
      color:
        (v.info?.severity?.toUpperCase() || "INFO") === "CRITICAL"
          ? "#ef4444"
          : (v.info?.severity?.toUpperCase() || "INFO") === "HIGH"
          ? "#f97316"
          : (v.info?.severity?.toUpperCase() || "INFO") === "MEDIUM"
          ? "#eab308"
          : (v.info?.severity?.toUpperCase() || "INFO") === "LOW"
          ? "#3b82f6"
          : "#6b7280",
      details: {
        type: "Vulnerability Threat Target",
        name: v.info?.name || "Nuclei Finding",
        severity: v.info?.severity?.toUpperCase() || "INFO",
        description: v.info?.description || "No description available.",
        matcher: v["matched-at"] || "Matched signature block",
        evidence: "",
      },
      matchedAt: v["matched-at"] || "",
    })),
    ...leaks.map((l, idx) => ({
      id: `leak_${idx}`,
      label: l.type,
      type: "leak",
      color: l.severity === "CRITICAL" ? "#ef4444" : "#f97316",
      details: {
        type: "Native Critical Leak Alert",
        name: l.type,
        severity: l.severity,
        description: l.description,
        matcher: l.path,
        evidence: l.evidence,
      },
      matchedAt: l.path,
    })),
    ...cves.map((c, idx) => {
      const isKevActive = kevs.some((k) => k.cve_id.toUpperCase() === c.id.toUpperCase());
      return {
        id: `cve_${idx}`,
        label: c.id,
        type: "cve",
        color: isKevActive ? "#ef4444" : "#a78bfa",
        details: {
          type: isKevActive ? "🚨 CISA KEV ACTIVE THREAT" : "Correlated CVE & MITRE ATT&CK",
          name: `${c.id}: ${c.name}`,
          severity: isKevActive ? "CRITICAL" : (c.cvss >= 9.0 ? "CRITICAL" : c.cvss >= 7.0 ? "HIGH" : "MEDIUM"),
          description: isKevActive 
            ? `🚨 CISA WARNING: This vulnerability is actively exploited in the wild! ${c.description}`
            : c.description,
          matcher: `MITRE Tactic: ${c.mitre_tactic} | Technique: ${c.mitre_technique} | EPSS Exploit Prob: ${(c.epss * 100).toFixed(0)}%`,
          evidence: `CVSS Score: ${c.cvss} | EPSS: ${c.epss}`,
        },
        matchedAt: c.id,
      };
    }),
  ];

  const threatsYSpacing = Math.max(80, height / (threats.length + 1));
  threats.forEach((t, idx) => {
    const y = threatsYSpacing * (idx + 1);
    const threatNode = {
      id: t.id,
      label: t.label,
      type: t.type,
      x: 860,
      y: y,
      color: t.color,
      details: t.details,
    };
    nodes.push(threatNode);

    // Link threat node to either a matching port or root
    let linked = false;
    ports.forEach((p, pIdx) => {
      const portNum = p.port.split("/")[0];
      if (t.matchedAt.includes(`:${portNum}`) || t.matchedAt.includes(`/${portNum}`)) {
        const portNodeRef = nodes.find((n) => n.id === `port_${pIdx}`);
        if (portNodeRef) {
          links.push({ from: portNodeRef, to: threatNode });
          linked = true;
        }
      }
    });
    if (!linked) {
      links.push({ from: rootNode, to: threatNode });
    }
  });

  return (
    <div className="relative flex-1 flex flex-col h-full bg-neutral-950/20 rounded-xl overflow-hidden min-h-[500px]">
      <div className="flex-1 w-full relative overflow-auto custom-scrollbar">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-auto min-w-[800px] select-none"
        >
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="1" />
            </pattern>
          </defs>
          <rect width={width} height={height} fill="url(#grid)" />

          {/* Links */}
          {links.map((link, idx) => {
            if (!link.from || !link.to) return null;
            const x1 = link.from.x;
            const y1 = link.from.y;
            const x2 = link.to.x;
            const y2 = link.to.y;
            const dx = Math.abs(x2 - x1) * 0.5;
            const pathData = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

            return (
              <g key={idx}>
                <path
                  d={pathData}
                  fill="none"
                  stroke={link.to.color}
                  strokeWidth="4"
                  className="opacity-10"
                />
                <path
                  d={pathData}
                  fill="none"
                  stroke={link.to.color}
                  strokeWidth="1.5"
                  className="opacity-45"
                  strokeDasharray="4,4"
                />
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const isSelected = selectedNode?.id === node.id;
            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={() => setSelectedNode(node)}
                className="cursor-pointer group"
              >
                {node.type === "root" && (
                  <>
                    <circle r="22" fill="none" stroke={node.color} strokeWidth="1.5" className="animate-ping opacity-25" />
                    <circle r="30" fill="none" stroke={node.color} strokeWidth="1" className="animate-pulse opacity-10" />
                  </>
                )}

                <circle
                  r={node.type === "root" ? 18 : 12}
                  fill="#000"
                  stroke={node.color}
                  strokeWidth={isSelected ? 3 : 1.5}
                  className="transition-all duration-300 shadow-[0_0_10px_rgba(255,255,255,0.2)]"
                />

                <circle
                  r={node.type === "root" ? 8 : 5}
                  fill={node.color}
                  className="group-hover:scale-125 transition-transform duration-200"
                />

                <text
                  y={node.type === "root" ? 34 : 26}
                  textAnchor="middle"
                  fill="#e5e5e5"
                  fontSize="10"
                  fontWeight={node.type === "root" ? "bold" : "normal"}
                  className="font-mono bg-black/60 px-1 select-none"
                >
                  {node.label.length > 20 ? node.label.substring(0, 17) + "..." : node.label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Floating Info Overlay */}
      {selectedNode && (
        <div className="absolute right-4 bottom-4 w-72 bg-black/80 backdrop-blur-md border border-white/10 rounded-xl p-4 shadow-2xl animate-in fade-in slide-in-from-bottom-3 duration-200">
          <div className="flex justify-between items-start mb-2">
            <span
              className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border"
              style={{
                borderColor: selectedNode.color + "40",
                color: selectedNode.color,
                backgroundColor: selectedNode.color + "10",
              }}
            >
              {selectedNode.details.type}
            </span>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-neutral-500 hover:text-white text-xs cursor-pointer"
            >
              ✕
            </button>
          </div>

          <div className="text-white space-y-2 mt-2">
            {selectedNode.type === "root" && (
              <>
                <div className="text-sm font-bold truncate">{selectedNode.details.address}</div>
                <div className="grid grid-cols-3 gap-2 pt-2 border-t border-white/5 text-center text-xs">
                  <div>
                    <div className="text-neutral-500 text-[10px] uppercase">Subs</div>
                    <div className="font-bold text-cyan-400">{selectedNode.details.subdomainsCount}</div>
                  </div>
                  <div>
                    <div className="text-neutral-500 text-[10px] uppercase">Ports</div>
                    <div className="font-bold text-indigo-400">{selectedNode.details.portsCount}</div>
                  </div>
                  <div>
                    <div className="text-neutral-500 text-[10px] uppercase">Threats</div>
                    <div className="font-bold text-red-400">{selectedNode.details.vulnsCount}</div>
                  </div>
                </div>
              </>
            )}

            {selectedNode.type === "subdomain" && (
              <>
                <div className="text-sm font-bold truncate">{selectedNode.details.hostname}</div>
                <div className="text-neutral-500 text-xs">DNS CNAME target successfully parsed.</div>
              </>
            )}

            {selectedNode.type === "port" && (
              <>
                <div className="text-sm font-bold text-indigo-400">{selectedNode.details.port}</div>
                <div className="text-xs space-y-1">
                  <div><span className="text-neutral-500">Service:</span> <span className="text-neutral-200">{selectedNode.details.service}</span></div>
                  <div><span className="text-neutral-500">Version:</span> <span className="text-neutral-300 font-mono">{selectedNode.details.version}</span></div>
                </div>
              </>
            )}

            {selectedNode.type === "vulnerability" && (
              <>
                <div className="text-sm font-bold text-red-400 leading-snug">{selectedNode.details.name}</div>
                <div className="text-xs max-h-32 overflow-y-auto custom-scrollbar text-neutral-400 leading-relaxed pr-1">
                  {selectedNode.details.description}
                </div>
                {selectedNode.details.matcher && (
                  <div className="pt-2 border-t border-white/5 text-[10px] text-neutral-500 truncate">
                    Matched: <span className="text-neutral-300 font-mono">{selectedNode.details.matcher}</span>
                  </div>
                )}
              </>
            )}

            {selectedNode.type === "leak" && (
              <>
                <div className="text-sm font-bold text-orange-400 leading-snug">{selectedNode.details.name}</div>
                <div className="text-xs max-h-24 overflow-y-auto custom-scrollbar text-neutral-400 leading-relaxed pr-1 mb-2">
                  {selectedNode.details.description}
                </div>
                {selectedNode.details.matcher && (
                  <div className="pt-1 text-[10px] text-neutral-500 truncate mb-1">
                    Path: <span className="text-neutral-300 font-mono">{selectedNode.details.matcher}</span>
                  </div>
                )}
                {selectedNode.details.evidence && (
                  <div className="pt-1.5 border-t border-white/5">
                    <pre className="bg-black/50 text-green-400 p-2 rounded text-[8px] font-mono overflow-x-auto max-h-24">{selectedNode.details.evidence}</pre>
                  </div>
                )}
              </>
            )}

            {selectedNode.type === "cve" && (
              <>
                <div className="text-sm font-bold text-purple-400 leading-snug">{selectedNode.details.name}</div>
                <div className="text-xs max-h-24 overflow-y-auto custom-scrollbar text-neutral-400 leading-relaxed pr-1 mb-2">
                  {selectedNode.details.description}
                </div>
                {selectedNode.details.matcher && (
                  <div className="pt-1 text-[10px] text-neutral-400 leading-normal mb-1">
                    {selectedNode.details.matcher}
                  </div>
                )}
                {selectedNode.details.evidence && (
                  <div className="pt-1.5 border-t border-white/5 text-[10px] text-neutral-500 font-mono">
                    {selectedNode.details.evidence}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

interface MitreAttackMatrixProps {
  events: any[];
}

function MitreAttackMatrix({ events }: MitreAttackMatrixProps) {
  const [hoveredTech, setHoveredTech] = useState<any>(null);

  // Extract MITRE techniques from active cve events
  const activeTechniques = events
    .filter((e) => e.type === "cve")
    .map((e) => e.data.mitre_technique);

  const tactics = [
    {
      name: "Reconnaissance",
      techniques: [
        { id: "T1592", name: "Gather Host Info", desc: "Gather details about victim host, including version banners, operating systems, and services." },
        { id: "T1595", name: "Active Scanning", desc: "Probing target network to map ports and active services using scanners." }
      ]
    },
    {
      name: "Initial Access",
      techniques: [
        { id: "T1190", name: "Exploit Public App", desc: "Exploit weakness in internet-facing service or application to gain unauthorized access." },
        { id: "T1133", name: "External Remote Services", desc: "Leverage public remote administration interfaces (VPN, SSH, RDP) to enter network." }
      ]
    },
    {
      name: "Execution",
      techniques: [
        { id: "T1059", name: "Command Interpreter", desc: "Execute commands or custom code using CLI interpreters (SCP, bash, PowerShell)." },
        { id: "T1203", name: "Client Exploitation", desc: "Exploit software vulnerabilities inside target client applications." }
      ]
    },
    {
      name: "Credential Access",
      techniques: [
        { id: "T1552", name: "Unsecured Credentials", desc: "Exposed configuration files (.env, backups) containing credentials or API secrets." },
        { id: "T1552.001", name: "Credentials In Files", desc: "Access source control config archives (.git/config) containing password entries." }
      ]
    },
    {
      name: "Lateral Movement",
      techniques: [
        { id: "T1210", name: "Exploit Remote Service", desc: "Leverage exploit payloads to pivot or execute arbitrary code on adjacent services (Lua sandbox escape)." },
        { id: "T1021", name: "Remote Services", desc: "Use remote control protocols (SSH, FTP) to authenticate and pivot across hosts." }
      ]
    },
    {
      name: "Collection",
      techniques: [
        { id: "T1560", name: "Archive Collected Data", desc: "Retrieve compressed source archives (.zip, .tar.gz) or SQL backups from public servers." },
        { id: "T1115", name: "Clipboard Data", desc: "Access clipboard content containing target host information." }
      ]
    }
  ];

  return (
    <div className="flex-1 flex flex-col bg-neutral-950 p-6 rounded-xl border border-white/5 min-h-[500px]">
      <div className="flex items-center gap-3 border-b border-white/5 pb-4 mb-6">
        <div className="w-2.5 h-2.5 rounded-full bg-purple-500 animate-pulse"></div>
        <h2 className="text-lg font-bold bg-gradient-to-r from-purple-400 to-indigo-400 bg-clip-text text-transparent uppercase tracking-wider font-mono">
          MITRE ATT&CK Threat Alignment Matrix
        </h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4 flex-1">
        {tactics.map((tactic) => (
          <div key={tactic.name} className="flex flex-col border border-white/5 rounded-xl bg-neutral-900/10 p-3">
            <h3 className="text-neutral-400 font-mono text-[10px] uppercase font-bold tracking-wider mb-3 text-center border-b border-white/5 pb-2">
              {tactic.name}
            </h3>
            <div className="space-y-3 flex-1 flex flex-col justify-start">
              {tactic.techniques.map((tech) => {
                const isActive = activeTechniques.includes(tech.id);
                return (
                  <div
                    key={tech.id}
                    onMouseEnter={() => setHoveredTech(tech)}
                    onMouseLeave={() => setHoveredTech(null)}
                    className={`relative p-3 rounded-lg border transition-all cursor-help text-left select-none ${
                      isActive
                        ? "bg-purple-950/20 border-purple-500/80 shadow-[0_0_15px_rgba(167,139,250,0.15)]"
                        : "bg-neutral-900/40 border-neutral-800 hover:border-neutral-700"
                    }`}
                  >
                    <div className="flex justify-between items-center mb-1">
                      <span className={`text-[9px] font-bold font-mono ${isActive ? "text-purple-400" : "text-neutral-500"}`}>
                        {tech.id}
                      </span>
                      {isActive && <span className="w-1.5 h-1.5 rounded-full bg-red-500 shadow-sm shadow-red-500/50 animate-pulse"></span>}
                    </div>
                    <div className={`text-xs font-bold ${isActive ? "text-white" : "text-neutral-400"}`}>
                      {tech.name}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 border border-white/5 rounded-xl p-4 bg-neutral-900/20 font-mono h-24 shrink-0 flex flex-col justify-center">
        {hoveredTech ? (
          <div className="space-y-1">
            <div className="text-xs font-bold text-purple-400">
              {hoveredTech.id} - {hoveredTech.name}
            </div>
            <div className="text-[11px] text-neutral-400 leading-relaxed">
              {hoveredTech.desc}
            </div>
          </div>
        ) : (
          <div className="text-xs text-neutral-500 text-center italic">
            Hover over a technique cell to view description and threat vectors.
          </div>
        )}
      </div>
    </div>
  );
}
