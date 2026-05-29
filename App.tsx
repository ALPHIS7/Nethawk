/**
 * NetHawk — Professional Network Intelligence Scanner
 * Next-generation IP scanner with real-time monitoring,
 * network topology visualization, and advanced device detection.
 * + CFCIA — Cloudflare Clean IP Attacher
 */

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import {
  AreaChart, Area, LineChart, Line, BarChart, Bar,
  ResponsiveContainer, Tooltip, XAxis, YAxis
} from "recharts";
import * as d3 from "d3";
import CFCIA from "./CFCIA";

/* Backend URL — started by nethawk_server.py / nethawk.exe */
// const API_BASE = "http://127.0.0.1:8747";

/* ═══════════════════════════════════════════════════════════════
   THEME & GLOBAL CSS
═══════════════════════════════════════════════════════════════ */
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;900&family=JetBrains+Mono:wght@300;400;500;600&family=Inter:wght@300;400;500&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg-void:    #06090f;
    --bg-deep:    #0a0e1a;
    --bg-card:    #0d1220;
    --bg-hover:   #111827;
    --bg-input:   #0a0e1a;
    --border:     rgba(0,255,157,0.15);
    --border-hi:  rgba(0,255,157,0.4);
    --border-dim: rgba(255,255,255,0.06);
    --green:      #00ff9d;
    --green-dim:  rgba(0,255,157,0.6);
    --cyan:       #00e5ff;
    --purple:     #a855f7;
    --orange:     #f97316;
    --red:        #ef4444;
    --yellow:     #eab308;
    --text-1:     #e2e8f0;
    --text-2:     #94a3b8;
    --text-3:     #475569;
    --font-head:  'Orbitron', monospace;
    --font-data:  'JetBrains Mono', monospace;
    --font-ui:    'Inter', sans-serif;
    --r:          8px;
  }

  html, body, #root { height: 100%; }

  .nethawk-app {
    display: flex;
    height: 100vh;
    min-height: 600px;
    background: var(--bg-void);
    color: var(--text-1);
    font-family: var(--font-ui);
    overflow: hidden;
    position: relative;
  }

  /* Scanline overlay */
  .nethawk-app::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.03) 2px,
      rgba(0,0,0,0.03) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  /* ─── SIDEBAR ─── */
  .sidebar {
    width: 220px;
    min-width: 220px;
    background: var(--bg-deep);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding: 20px 0;
    position: relative;
    overflow: hidden;
    z-index: 10;
  }
  .sidebar::after {
    content: '';
    position: absolute;
    right: 0; top: 0; bottom: 0;
    width: 1px;
    background: linear-gradient(to bottom, transparent, var(--green), transparent);
    animation: scan-line 3s ease-in-out infinite;
    opacity: 0.6;
  }
  @keyframes scan-line {
    0%,100% { opacity: 0; transform: scaleY(0) translateY(-100%); }
    50% { opacity: 0.6; transform: scaleY(1) translateY(0); }
  }
  .logo {
    padding: 0 20px 24px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 8px;
  }
  .logo-text {
    font-family: var(--font-head);
    font-size: 18px;
    font-weight: 900;
    color: var(--green);
    letter-spacing: 3px;
    text-shadow: 0 0 20px rgba(0,255,157,0.5);
  }
  .logo-sub {
    font-family: var(--font-data);
    font-size: 9px;
    color: var(--text-3);
    letter-spacing: 2px;
    margin-top: 2px;
  }
  .nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 11px 20px;
    cursor: pointer;
    font-size: 12px;
    font-family: var(--font-data);
    color: var(--text-2);
    letter-spacing: 0.5px;
    border-left: 2px solid transparent;
    transition: all 0.15s ease;
    user-select: none;
  }
  .nav-item:hover { color: var(--text-1); background: var(--bg-hover); }
  .nav-item.active {
    color: var(--green);
    border-left-color: var(--green);
    background: rgba(0,255,157,0.05);
    text-shadow: 0 0 10px rgba(0,255,157,0.3);
  }
  .nav-item.active-cyan {
    color: var(--cyan) !important;
    border-left-color: var(--cyan) !important;
    background: rgba(0,229,255,0.05) !important;
    text-shadow: 0 0 10px rgba(0,229,255,0.3) !important;
  }
  .nav-icon { width: 16px; height: 16px; opacity: 0.7; flex-shrink: 0; }
  .nav-item.active .nav-icon { opacity: 1; filter: drop-shadow(0 0 4px var(--green)); }
  .nav-item.active-cyan .nav-icon { opacity: 1; filter: drop-shadow(0 0 4px var(--cyan)) !important; }
  .nav-badge {
    margin-left: auto;
    background: rgba(0,255,157,0.15);
    color: var(--green);
    font-size: 9px;
    padding: 2px 6px;
    border-radius: 10px;
    border: 1px solid var(--border);
  }
  .nav-badge-cyan {
    margin-left: auto;
    background: rgba(0,229,255,0.15);
    color: var(--cyan);
    font-size: 9px;
    padding: 2px 6px;
    border-radius: 10px;
    border: 1px solid rgba(0,229,255,0.3);
  }
  .nav-section {
    font-size: 9px;
    font-family: var(--font-data);
    letter-spacing: 2px;
    color: var(--text-3);
    padding: 16px 20px 4px;
    text-transform: uppercase;
  }
  .sidebar-footer {
    margin-top: auto;
    padding: 16px 20px;
    border-top: 1px solid var(--border);
  }
  .status-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
    animation: pulse-dot 2s ease-in-out infinite;
    display: inline-block;
  }
  @keyframes pulse-dot {
    0%,100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(0.8); }
  }
  .sidebar-status {
    font-size: 10px;
    font-family: var(--font-data);
    color: var(--text-3);
    display: flex;
    align-items: center;
    gap: 6px;
    margin-top: 6px;
  }

  /* ─── MAIN CONTENT ─── */
  .main-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    background: var(--bg-void);
  }
  .topbar {
    height: 52px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-deep);
    display: flex;
    align-items: center;
    padding: 0 24px;
    gap: 16px;
    flex-shrink: 0;
  }
  .topbar-title {
    font-family: var(--font-head);
    font-size: 12px;
    letter-spacing: 2px;
    color: var(--text-2);
    text-transform: uppercase;
  }
  .topbar-title span { color: var(--green); }
  .topbar-title span.cyan { color: var(--cyan); }
  .topbar-spacer { flex: 1; }
  .topbar-badge {
    font-family: var(--font-data);
    font-size: 10px;
    color: var(--text-3);
    padding: 3px 10px;
    border: 1px solid var(--border-dim);
    border-radius: 4px;
    letter-spacing: 1px;
  }
  .page-scroll {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    scrollbar-width: thin;
    scrollbar-color: var(--border) transparent;
  }
  .page-scroll::-webkit-scrollbar { width: 4px; }
  .page-scroll::-webkit-scrollbar-track { background: transparent; }
  .page-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  /* ─── CARDS ─── */
  .card {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    border-radius: var(--r);
    padding: 18px 20px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
  }
  .card:hover { border-color: var(--border); }
  .card-title {
    font-family: var(--font-head);
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--text-3);
    text-transform: uppercase;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .card-title::before {
    content: '';
    width: 3px; height: 3px;
    background: var(--green);
    border-radius: 50%;
    box-shadow: 0 0 4px var(--green);
  }

  /* ─── STAT CARDS ─── */
  .stat-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 14px; margin-bottom: 20px; }
  .stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    border-radius: var(--r);
    padding: 16px 18px;
    position: relative;
    overflow: hidden;
    cursor: default;
    transition: all 0.2s;
  }
  .stat-card:hover { border-color: var(--border); transform: translateY(-1px); }
  .stat-card::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
  }
  .stat-card.green::after { background: linear-gradient(90deg, transparent, var(--green), transparent); }
  .stat-card.cyan::after  { background: linear-gradient(90deg, transparent, var(--cyan), transparent); }
  .stat-card.purple::after { background: linear-gradient(90deg, transparent, var(--purple), transparent); }
  .stat-card.orange::after { background: linear-gradient(90deg, transparent, var(--orange), transparent); }
  .stat-label { font-size: 10px; font-family: var(--font-data); color: var(--text-3); letter-spacing: 1px; margin-bottom: 8px; }
  .stat-value { font-family: var(--font-head); font-size: 28px; font-weight: 700; }
  .stat-value.green { color: var(--green); text-shadow: 0 0 20px rgba(0,255,157,0.4); }
  .stat-value.cyan  { color: var(--cyan);  text-shadow: 0 0 20px rgba(0,229,255,0.4); }
  .stat-value.purple{ color: var(--purple);text-shadow: 0 0 20px rgba(168,85,247,0.4); }
  .stat-value.orange{ color: var(--orange);text-shadow: 0 0 20px rgba(249,115,22,0.4); }
  .stat-change { font-size: 11px; font-family: var(--font-data); color: var(--text-3); margin-top: 4px; }
  .stat-change.up { color: var(--green); }

  /* ─── GRID LAYOUTS ─── */
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 14px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; margin-bottom: 14px; }
  .col-span-2 { grid-column: span 2; }

  /* ─── BUTTONS ─── */
  .btn {
    font-family: var(--font-data);
    font-size: 11px;
    letter-spacing: 1px;
    padding: 9px 18px;
    border-radius: 5px;
    border: 1px solid;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    transition: all 0.15s;
    user-select: none;
    text-transform: uppercase;
    font-weight: 500;
  }
  .btn-primary {
    background: rgba(0,255,157,0.1);
    border-color: var(--green);
    color: var(--green);
    text-shadow: 0 0 8px rgba(0,255,157,0.4);
  }
  .btn-primary:hover {
    background: rgba(0,255,157,0.2);
    box-shadow: 0 0 20px rgba(0,255,157,0.2);
  }
  .btn-primary:active { transform: scale(0.98); }
  .btn-primary.running {
    animation: btn-pulse 1.5s ease-in-out infinite;
    background: rgba(0,255,157,0.15);
  }
  @keyframes btn-pulse {
    0%,100% { box-shadow: 0 0 8px rgba(0,255,157,0.3); }
    50% { box-shadow: 0 0 25px rgba(0,255,157,0.5); }
  }
  .btn-secondary {
    background: transparent;
    border-color: var(--border);
    color: var(--text-2);
  }
  .btn-secondary:hover { border-color: var(--border-hi); color: var(--text-1); }
  .btn-danger {
    background: rgba(239,68,68,0.1);
    border-color: var(--red);
    color: var(--red);
  }
  .btn-sm { padding: 5px 12px; font-size: 10px; }

  /* ─── INPUTS ─── */
  .input-group { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .input-field {
    flex: 1;
    min-width: 200px;
    background: var(--bg-input);
    border: 1px solid var(--border-dim);
    border-radius: 5px;
    padding: 9px 14px;
    font-family: var(--font-data);
    font-size: 12px;
    color: var(--text-1);
    outline: none;
    transition: border-color 0.2s;
  }
  .input-field:focus { border-color: var(--green); box-shadow: 0 0 12px rgba(0,255,157,0.1); }
  .input-field::placeholder { color: var(--text-3); }
  .input-label {
    font-size: 10px;
    font-family: var(--font-data);
    color: var(--text-3);
    letter-spacing: 1px;
    margin-bottom: 6px;
  }
  .select-field {
    background: var(--bg-input);
    border: 1px solid var(--border-dim);
    border-radius: 5px;
    padding: 8px 12px;
    font-family: var(--font-data);
    font-size: 11px;
    color: var(--text-1);
    outline: none;
    cursor: pointer;
  }
  .select-field:focus { border-color: var(--green); }

  /* ─── PROGRESS ─── */
  .progress-wrap {
    background: rgba(0,0,0,0.4);
    border-radius: 3px;
    height: 4px;
    overflow: hidden;
    border: 1px solid var(--border-dim);
  }
  .progress-bar {
    height: 100%;
    background: linear-gradient(90deg, var(--green), var(--cyan));
    border-radius: 3px;
    transition: width 0.3s ease;
    position: relative;
    box-shadow: 0 0 8px var(--green);
  }
  .progress-bar::after {
    content: '';
    position: absolute;
    right: 0; top: -1px; bottom: -1px;
    width: 20px;
    background: rgba(255,255,255,0.6);
    filter: blur(4px);
    animation: shimmer 1.5s ease-in-out infinite;
  }
  @keyframes shimmer {
    0%,100% { opacity: 0; }
    50% { opacity: 1; }
  }

  /* ─── DEVICE TABLE ─── */
  .device-table { width: 100%; border-collapse: collapse; font-family: var(--font-data); }
  .device-table th {
    font-size: 9px;
    letter-spacing: 2px;
    color: var(--text-3);
    text-transform: uppercase;
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border-dim);
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
  }
  .device-table th:hover { color: var(--text-2); }
  .device-table td {
    padding: 10px 12px;
    font-size: 11px;
    color: var(--text-2);
    border-bottom: 1px solid rgba(255,255,255,0.03);
    vertical-align: middle;
  }
  .device-table tr { transition: background 0.1s; }
  .device-table tr:hover td { background: rgba(0,255,157,0.03); color: var(--text-1); }
  .device-table tr.expanded td { background: rgba(0,255,157,0.05); }

  .ip-cell { color: var(--cyan); font-weight: 500; }
  .hostname-cell { color: var(--text-1); }
  .mac-cell { color: var(--text-3); font-size: 10px; }
  .vendor-cell { color: var(--purple); font-size: 10px; }

  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 9px;
    padding: 3px 8px;
    border-radius: 10px;
    letter-spacing: 1px;
    font-weight: 600;
  }
  .status-badge.online {
    background: rgba(0,255,157,0.1);
    border: 1px solid rgba(0,255,157,0.3);
    color: var(--green);
  }
  .status-badge.offline {
    background: rgba(239,68,68,0.08);
    border: 1px solid rgba(239,68,68,0.2);
    color: var(--red);
  }
  .status-badge.unknown {
    background: rgba(255,255,255,0.05);
    border: 1px solid var(--border-dim);
    color: var(--text-3);
  }
  .status-badge .dot {
    width: 5px; height: 5px;
    border-radius: 50%;
    background: currentColor;
  }
  .status-badge.online .dot { animation: pulse-dot 1.5s infinite; }

  .latency-cell { color: var(--text-2); }
  .latency-cell.fast { color: var(--green); }
  .latency-cell.slow { color: var(--yellow); }
  .latency-cell.dead { color: var(--red); }

  .ports-mini {
    display: flex; gap: 3px; flex-wrap: wrap; max-width: 160px;
  }
  .port-chip {
    font-size: 9px;
    padding: 1px 5px;
    border-radius: 3px;
    border: 1px solid;
  }
  .port-chip.open {
    background: rgba(0,229,255,0.08);
    border-color: rgba(0,229,255,0.3);
    color: var(--cyan);
  }
  .port-chip.filtered {
    background: rgba(234,179,8,0.08);
    border-color: rgba(234,179,8,0.3);
    color: var(--yellow);
  }

  .expand-btn {
    background: none;
    border: none;
    color: var(--text-3);
    cursor: pointer;
    padding: 2px 6px;
    font-size: 14px;
    transition: color 0.15s, transform 0.15s;
  }
  .expand-btn:hover { color: var(--green); }
  .expand-btn.expanded { transform: rotate(90deg); color: var(--green); }

  /* ─── EXPANDED DEVICE ROW ─── */
  .device-detail {
    padding: 16px 20px;
    background: rgba(0,255,157,0.02);
    border-bottom: 1px solid var(--border-dim);
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
  }
  .detail-section-title {
    font-size: 9px;
    font-family: var(--font-data);
    letter-spacing: 2px;
    color: var(--text-3);
    margin-bottom: 8px;
    text-transform: uppercase;
  }
  .detail-kv { display: flex; flex-direction: column; gap: 5px; }
  .detail-row { display: flex; justify-content: space-between; font-size: 11px; }
  .detail-row .k { color: var(--text-3); }
  .detail-row .v { color: var(--text-1); font-weight: 500; }
  .ports-detail { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px; }
  .port-detail-chip {
    font-size: 10px;
    font-family: var(--font-data);
    padding: 3px 8px;
    border-radius: 4px;
    border: 1px solid;
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .port-detail-chip.open { background: rgba(0,229,255,0.08); border-color: rgba(0,229,255,0.3); color: var(--cyan); }
  .port-detail-chip.closed { background: rgba(239,68,68,0.08); border-color: rgba(239,68,68,0.2); color: var(--red); }
  .port-detail-chip.filtered { background: rgba(234,179,8,0.08); border-color: rgba(234,179,8,0.2); color: var(--yellow); }

  /* ─── SCANNER ANIMATION ─── */
  .scan-animation {
    display: flex;
    flex-direction: column;
    gap: 4px;
    height: 140px;
    overflow: hidden;
    position: relative;
    font-family: var(--font-data);
    font-size: 10px;
  }
  .scan-animation::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 40px;
    background: linear-gradient(to top, var(--bg-card), transparent);
  }
  .scan-line-item {
    color: var(--text-3);
    letter-spacing: 0.5px;
    animation: fade-in 0.3s ease;
  }
  .scan-line-item.found { color: var(--green); }
  .scan-line-item.port  { color: var(--cyan); }
  @keyframes fade-in { from { opacity: 0; transform: translateX(-8px); } to { opacity: 1; transform: none; } }

  /* ─── NETWORK MAP ─── */
  #network-map-svg {
    width: 100%; height: 100%;
    cursor: grab;
  }
  #network-map-svg:active { cursor: grabbing; }
  .map-node text { font-family: var(--font-data); }
  .map-link { stroke-dasharray: 4 2; animation: dash-flow 1.5s linear infinite; }
  @keyframes dash-flow { to { stroke-dashoffset: -12; } }

  /* ─── LIVE MONITOR ─── */
  .monitor-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
  .monitor-card {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    border-radius: var(--r);
    padding: 14px;
    position: relative;
    overflow: hidden;
    transition: all 0.2s;
  }
  .monitor-card.online { border-color: rgba(0,255,157,0.2); }
  .monitor-card.offline { border-color: rgba(239,68,68,0.15); opacity: 0.7; }
  .monitor-card-ip { font-family: var(--font-data); font-size: 13px; color: var(--cyan); font-weight: 500; }
  .monitor-card-name { font-size: 11px; color: var(--text-2); margin-top: 2px; margin-bottom: 10px; }
  .mini-chart-wrap { height: 40px; }
  .monitor-latency { font-family: var(--font-data); font-size: 10px; color: var(--text-3); margin-top: 6px; }

  /* ─── PORT SCANNER ─── */
  .port-result-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
    gap: 6px;
    margin-top: 16px;
  }
  .port-result-tile {
    background: var(--bg-deep);
    border: 1px solid var(--border-dim);
    border-radius: 5px;
    padding: 8px 10px;
    font-family: var(--font-data);
    font-size: 10px;
    cursor: default;
    transition: all 0.15s;
    animation: fade-in 0.3s ease;
  }
  .port-result-tile:hover { transform: translateY(-1px); }
  .port-result-tile.open { border-color: rgba(0,229,255,0.3); background: rgba(0,229,255,0.05); }
  .port-result-tile.closed { border-color: rgba(255,255,255,0.05); opacity: 0.5; }
  .port-result-tile.filtered { border-color: rgba(234,179,8,0.3); background: rgba(234,179,8,0.05); }
  .port-num { font-size: 13px; font-weight: 600; color: var(--text-1); }
  .port-state { font-size: 9px; letter-spacing: 1px; margin-top: 2px; }
  .port-state.open { color: var(--cyan); }
  .port-state.closed { color: var(--text-3); }
  .port-state.filtered { color: var(--yellow); }
  .port-service { font-size: 9px; color: var(--text-3); margin-top: 1px; }

  /* ─── HISTORY ─── */
  .history-row {
    display: flex;
    align-items: center;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border-dim);
    gap: 16px;
    font-family: var(--font-data);
    font-size: 11px;
    transition: background 0.1s;
    cursor: default;
  }
  .history-row:hover { background: var(--bg-hover); }
  .history-time { color: var(--text-3); font-size: 10px; min-width: 130px; }
  .history-range { color: var(--cyan); min-width: 150px; }
  .history-found { color: var(--green); min-width: 80px; }
  .history-duration { color: var(--text-2); min-width: 60px; }

  /* ─── TOOLTIP override ─── */
  .recharts-tooltip-wrapper .recharts-default-tooltip {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 4px !important;
    font-family: var(--font-data) !important;
    font-size: 10px !important;
  }

  /* ─── SEARCH ─── */
  .search-wrap {
    position: relative;
    display: inline-flex;
    align-items: center;
  }
  .search-icon {
    position: absolute;
    left: 10px;
    color: var(--text-3);
    pointer-events: none;
    font-size: 13px;
  }
  .search-field {
    background: var(--bg-input);
    border: 1px solid var(--border-dim);
    border-radius: 5px;
    padding: 7px 12px 7px 30px;
    font-family: var(--font-data);
    font-size: 11px;
    color: var(--text-1);
    outline: none;
    width: 220px;
    transition: border-color 0.2s;
  }
  .search-field:focus { border-color: var(--green); }
  .search-field::placeholder { color: var(--text-3); }

  /* ─── OS BADGE ─── */
  .os-badge {
    font-size: 9px;
    font-family: var(--font-data);
    padding: 2px 7px;
    border-radius: 3px;
    background: rgba(168,85,247,0.1);
    border: 1px solid rgba(168,85,247,0.2);
    color: var(--purple);
    white-space: nowrap;
  }

  /* ─── EXPORT BAR ─── */
  .export-bar {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }

  /* ─── TERMINAL LOG ─── */
  .terminal-log {
    background: #0a0a0a;
    border: 1px solid var(--border-dim);
    border-radius: 6px;
    padding: 14px;
    height: 200px;
    overflow-y: auto;
    font-family: var(--font-data);
    font-size: 10px;
    color: var(--text-3);
    line-height: 1.8;
    scrollbar-width: thin;
    scrollbar-color: var(--border-dim) transparent;
  }
  .terminal-log .t-green { color: var(--green); }
  .terminal-log .t-cyan  { color: var(--cyan); }
  .terminal-log .t-red   { color: var(--red); }
  .terminal-log .t-yellow{ color: var(--yellow); }
  .terminal-log .t-dim   { color: var(--text-3); }

  /* ─── RANGE SLIDER ─── */
  .range-wrap { display: flex; align-items: center; gap: 10px; }
  .range-input {
    -webkit-appearance: none;
    flex: 1;
    height: 3px;
    border-radius: 2px;
    background: var(--border-dim);
    outline: none;
  }
  .range-input::-webkit-slider-thumb {
    -webkit-appearance: none;
    width: 14px; height: 14px;
    border-radius: 50%;
    background: var(--green);
    cursor: pointer;
    box-shadow: 0 0 6px var(--green);
  }
  .range-val {
    font-family: var(--font-data);
    font-size: 11px;
    color: var(--green);
    min-width: 30px;
    text-align: right;
  }

  /* ─── SCROLLBAR for terminal ─── */
  .terminal-log::-webkit-scrollbar { width: 3px; }
  .terminal-log::-webkit-scrollbar-track { background: transparent; }
  .terminal-log::-webkit-scrollbar-thumb { background: var(--border-dim); }

  /* ─── FADE IN ANIMATION ─── */
  .page-enter { animation: page-in 0.25s ease; }
  @keyframes page-in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }

  /* ─── PROGRESS INDICATOR ─── */
  .scan-stats-row {
    display: flex; gap: 20px; align-items: center;
    font-family: var(--font-data); font-size: 11px; color: var(--text-3);
    margin-top: 8px;
  }
  .scan-stats-row span { color: var(--text-2); }
  .scan-stats-row .hi { color: var(--green); }

  /* ─── GLOW DIVIDER ─── */
  .glow-divider {
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--green), transparent);
    opacity: 0.3;
    margin: 4px 0 16px;
  }

  /* ─── CFCIA NAV SEPARATOR ─── */
  .nav-cfcia-sep {
    margin: 8px 20px;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(0,229,255,0.3), transparent);
  }
`;

/* ═══════════════════════════════════════════════════════════════
   SAMPLE DATA
═══════════════════════════════════════════════════════════════ */
const DEVICES = [
  { ip:"192.168.1.1",  hostname:"gateway.local",       mac:"A4:C3:F0:11:22:33", vendor:"Cisco Systems",    os:"IOS 15.x",          type:"Router",      latency:1,   status:"online",  ports:[{n:22,s:"open",svc:"SSH"},{n:80,s:"open",svc:"HTTP"},{n:443,s:"open",svc:"HTTPS"}], tags:["gateway","critical"] },
  { ip:"192.168.1.10", hostname:"homeserver.local",     mac:"B8:27:EB:AA:BB:CC", vendor:"Raspberry Pi",    os:"Linux 5.x",         type:"Server",      latency:4,   status:"online",  ports:[{n:22,s:"open",svc:"SSH"},{n:80,s:"open",svc:"HTTP"},{n:8080,s:"open",svc:"HTTP-ALT"},{n:3306,s:"filtered",svc:"MySQL"}], tags:["server"] },
  { ip:"192.168.1.15", hostname:"macbook-pro.local",    mac:"3C:22:FB:1A:2B:3C", vendor:"Apple Inc.",      os:"macOS 14.x",        type:"Laptop",      latency:8,   status:"online",  ports:[{n:22,s:"open",svc:"SSH"},{n:5900,s:"filtered",svc:"VNC"}], tags:[] },
  { ip:"192.168.1.20", hostname:"DESKTOP-W11",          mac:"00:1A:2B:3C:4D:5E", vendor:"Intel Corp.",     os:"Windows 11",        type:"Workstation", latency:12,  status:"online",  ports:[{n:135,s:"open",svc:"RPC"},{n:139,s:"open",svc:"NetBIOS"},{n:445,s:"open",svc:"SMB"},{n:3389,s:"filtered",svc:"RDP"}], tags:["windows"] },
  { ip:"192.168.1.25", hostname:"ubuntu-dev",           mac:"52:54:00:AB:CD:EF", vendor:"QEMU/KVM",        os:"Ubuntu 22.04",      type:"Virtual",     latency:3,   status:"online",  ports:[{n:22,s:"open",svc:"SSH"},{n:80,s:"open",svc:"HTTP"},{n:5432,s:"filtered",svc:"PostgreSQL"}], tags:["vm","dev"] },
  { ip:"192.168.1.30", hostname:"iPhone-Thomas",        mac:"DE:AD:BE:EF:01:23", vendor:"Apple Inc.",      os:"iOS 17.x",          type:"Phone",       latency:22,  status:"online",  ports:[], tags:["mobile"] },
  { ip:"192.168.1.35", hostname:"android-pixel",        mac:"F4:60:E2:11:22:33", vendor:"Google Inc.",     os:"Android 14",        type:"Phone",       latency:18,  status:"online",  ports:[], tags:["mobile"] },
  { ip:"192.168.1.40", hostname:"smart-tv-lg",          mac:"C4:36:6C:AA:BB:CC", vendor:"LG Electronics",  os:"webOS 22",          type:"SmartTV",     latency:35,  status:"online",  ports:[{n:8009,s:"open",svc:"Chromecast"}], tags:["iot"] },
  { ip:"192.168.1.45", hostname:"ring-doorbell",        mac:"78:8C:B5:01:02:03", vendor:"Ring LLC",        os:"Embedded Linux",    type:"IoT",         latency:55,  status:"online",  ports:[{n:443,s:"open",svc:"HTTPS"}], tags:["iot","security"] },
  { ip:"192.168.1.50", hostname:"nas-synology",         mac:"00:11:32:44:55:66", vendor:"Synology Inc.",   os:"DSM 7.x",           type:"NAS",         latency:6,   status:"online",  ports:[{n:22,s:"open",svc:"SSH"},{n:80,s:"open",svc:"HTTP"},{n:443,s:"open",svc:"HTTPS"},{n:5000,s:"open",svc:"DSM"},{n:5001,s:"open",svc:"DSM-SSL"}], tags:["storage","critical"] },
  { ip:"192.168.1.55", hostname:"printer-hp",           mac:"70:3A:CB:22:33:44", vendor:"HP Inc.",         os:"HP LaserJet",       type:"Printer",     latency:88,  status:"online",  ports:[{n:9100,s:"open",svc:"RAW Print"},{n:631,s:"open",svc:"IPP"}], tags:["peripheral"] },
  { ip:"192.168.1.60", hostname:"unknown-device",       mac:"B0:4E:26:FF:EE:DD", vendor:"Unknown",         os:"Unknown",           type:"Unknown",     latency:145, status:"online",  ports:[{n:80,s:"open",svc:"HTTP"}], tags:["suspicious"] },
  { ip:"192.168.1.65", hostname:"homelab-switch",       mac:"CC:2D:E0:11:22:33", vendor:"MikroTik",        os:"RouterOS 7.x",      type:"Switch",      latency:2,   status:"online",  ports:[{n:22,s:"open",svc:"SSH"},{n:80,s:"open",svc:"HTTP"},{n:443,s:"open",svc:"HTTPS"},{n:8291,s:"open",svc:"Winbox"}], tags:["network","critical"] },
  { ip:"192.168.1.70", hostname:"old-laptop",           mac:"11:22:33:44:55:66", vendor:"Dell Inc.",       os:"Windows 10",        type:"Laptop",      latency:0,   status:"offline", ports:[], tags:[] },
  { ip:"192.168.1.80", hostname:"camera-hikvision",     mac:"44:19:B6:AB:CD:EF", vendor:"Hikvision",       os:"Embedded Linux",    type:"Camera",      latency:210, status:"online",  ports:[{n:80,s:"open",svc:"HTTP"},{n:554,s:"open",svc:"RTSP"},{n:8000,s:"filtered",svc:"HIKVISION"}], tags:["iot","security"] },
  { ip:"192.168.1.100",hostname:"gaming-pc",            mac:"E8:6A:64:33:22:11", vendor:"ASUS",            os:"Windows 11",        type:"Workstation", latency:9,   status:"online",  ports:[{n:27015,s:"open",svc:"Steam"},{n:3074,s:"filtered",svc:"Xbox"}], tags:["gaming"] },
  { ip:"192.168.1.110",hostname:"",                     mac:"94:65:2D:55:44:33", vendor:"Amazon",          os:"Fire OS",           type:"SmartDevice", latency:41,  status:"online",  ports:[{n:443,s:"open",svc:"HTTPS"}], tags:["iot"] },
  { ip:"192.168.1.120",hostname:"backup-machine",       mac:"00:0C:29:AA:BB:CC", vendor:"VMware Inc.",     os:"Debian 12",         type:"Virtual",     latency:0,   status:"offline", ports:[], tags:["vm"] },
  { ip:"192.168.1.200",hostname:"vpn-endpoint",         mac:"02:42:AC:11:00:01", vendor:"WireGuard",       os:"Linux 6.x",         type:"VPN",         latency:22,  status:"online",  ports:[{n:51820,s:"open",svc:"WireGuard"},{n:22,s:"open",svc:"SSH"}], tags:["vpn","critical"] },
  { ip:"192.168.1.254",hostname:"isp-modem",            mac:"FC:EC:DA:00:11:22", vendor:"Arris Group",     os:"DOCSIS 3.1",        type:"Modem",       latency:3,   status:"online",  ports:[{n:80,s:"filtered",svc:"HTTP"}], tags:["critical"] },
];

const HISTORY = [
  { id:1, time:"2024-01-15 14:32:01", range:"192.168.1.0/24", found:18, online:16, duration:"12.4s", ports:47 },
  { id:2, time:"2024-01-15 10:15:33", range:"192.168.1.0/24", found:17, online:15, duration:"11.8s", ports:41 },
  { id:3, time:"2024-01-14 23:58:12", range:"10.0.0.0/24",    found:5,  online:5,  duration:"8.2s",  ports:12 },
  { id:4, time:"2024-01-14 18:30:00", range:"192.168.1.0/24", found:19, online:17, duration:"13.1s", ports:52 },
  { id:5, time:"2024-01-13 09:22:45", range:"192.168.2.0/24", found:3,  online:2,  duration:"9.5s",  ports:6  },
  { id:6, time:"2024-01-12 20:11:30", range:"192.168.1.0/24", found:16, online:14, duration:"10.9s", ports:38 },
];

const SERVICE_MAP: Record<number,string> = {
  21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP",
  110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB", 3306:"MySQL",
  3389:"RDP", 5432:"PostgreSQL", 5900:"VNC", 6379:"Redis", 8080:"HTTP-ALT",
  8443:"HTTPS-ALT", 27017:"MongoDB", 51820:"WireGuard", 9200:"Elasticsearch",
};

function genPingHistory(base: number, online: boolean) {
  return Array.from({length:30}, (_,i) => ({
    t: i,
    ms: online ? Math.max(1, base + Math.round((Math.random()-0.5)*base*0.6)) : null
  }));
}

function genBandwidth() {
  return Array.from({length:30}, (_,i) => ({
    t: i,
    rx: Math.round(50 + Math.random()*200),
    tx: Math.round(20 + Math.random()*100),
  }));
}

/* ═══════════════════════════════════════════════════════════════
   ICONS (inline SVG helpers)
═══════════════════════════════════════════════════════════════ */
const Icon = {
  Dashboard: () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="nav-icon"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>,
  Scanner:   () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="nav-icon"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/><path d="M11 8v6M8 11h6"/></svg>,
  Ports:     () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="nav-icon"><path d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>,
  Monitor:   () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="nav-icon"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  Map:       () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="nav-icon"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v3M12 10l-7 7M12 10l7 7"/></svg>,
  History:   () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="nav-icon"><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 15"/></svg>,
  Settings:  () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="nav-icon"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>,
  CFCIA:     () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="nav-icon"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>,
  Download:  () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" width="12" height="12"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>,
  Play:      () => <svg viewBox="0 0 24 24" fill="currentColor" width="12" height="12"><polygon points="5 3 19 12 5 21 5 3"/></svg>,
  Stop:      () => <svg viewBox="0 0 24 24" fill="currentColor" width="12" height="12"><rect x="3" y="3" width="18" height="18" rx="2"/></svg>,
  Sort:      () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" width="10" height="10"><path d="M3 6h18M7 12h10M11 18h2"/></svg>,
  Search:    () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="12" height="12"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>,
  Refresh:   () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" width="12" height="12"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>,
  Export:    () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" width="11" height="11"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>,
  Plus:      () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="11" height="11"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>,
  Chevron:   () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="12" height="12"><polyline points="9 18 15 12 9 6"/></svg>,
  Eye:       () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" width="11" height="11"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>,
};

/* ═══════════════════════════════════════════════════════════════
   SIDEBAR
═══════════════════════════════════════════════════════════════ */
function Sidebar({ active, setActive, scanRunning, deviceCount }: {
  active: string;
  setActive: (t: string) => void;
  scanRunning: boolean;
  deviceCount: number;
}) {
  const [time, setTime] = useState(() => new Date().toLocaleTimeString('en-US', { hour12:false }));
  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toLocaleTimeString('en-US', { hour12:false })), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <nav className="sidebar">
      <div className="logo">
        <div className="logo-text">NETHAWK</div>
        <div className="logo-sub">NETWORK INTELLIGENCE v2.4.1</div>
      </div>

      <div className="nav-section">MAIN</div>
      {[
        { id:"dashboard", label:"Dashboard",    icon:Icon.Dashboard },
        { id:"scanner",   label:"IP Scanner",   icon:Icon.Scanner, badge: scanRunning ? "LIVE" : null },
        { id:"ports",     label:"Port Scanner", icon:Icon.Ports },
      ].map(n => (
        <div key={n.id} className={`nav-item ${active===n.id?"active":""}`} onClick={()=>setActive(n.id)}>
          <n.icon/>
          {n.label}
          {n.badge && <span className="nav-badge">{n.badge}</span>}
        </div>
      ))}

      <div className="nav-section">MONITORING</div>
      {[
        { id:"monitor", label:"Live Monitor",  icon:Icon.Monitor },
        { id:"map",     label:"Network Map",   icon:Icon.Map },
        { id:"history", label:"Scan History",  icon:Icon.History },
      ].map(n => (
        <div key={n.id} className={`nav-item ${active===n.id?"active":""}`} onClick={()=>setActive(n.id)}>
          <n.icon/>
          {n.label}
        </div>
      ))}

      {/* CFCIA separator */}
      <div className="nav-cfcia-sep" />
      <div className="nav-section" style={{color:"rgba(0,229,255,0.5)"}}>TOOLS</div>

      <div
        className={`nav-item ${active==="cfcia" ? "active-cyan" : ""}`}
        onClick={() => setActive("cfcia")}
        style={active !== "cfcia" ? { color: "rgba(0,229,255,0.6)" } : {}}
      >
        <Icon.CFCIA/>
        CF Clean IP
        <span className="nav-badge-cyan">NEW</span>
      </div>

      <div className="nav-section">SYSTEM</div>
      <div className={`nav-item ${active==="settings"?"active":""}`} onClick={()=>setActive("settings")}>
        <Icon.Settings/>
        Settings
      </div>

      <div className="sidebar-footer">
        <div style={{fontSize:10,fontFamily:"var(--font-data)",color:"var(--text-3)",letterSpacing:1}}>
          NETWORK · 192.168.1.0/24
        </div>
        <div className="sidebar-status">
          <span className="status-dot"/>
          <span>{deviceCount} DEVICES · ONLINE</span>
        </div>
        <div className="sidebar-status" style={{marginTop:4}}>
          <span style={{color:"var(--text-3)"}}>⏱</span>
          <span style={{fontFamily:"var(--font-data)",fontSize:10,color:"var(--text-3)"}}>{time}</span>
        </div>
      </div>
    </nav>
  );
}

/* ═══════════════════════════════════════════════════════════════
   CUSTOM TOOLTIP for recharts
═══════════════════════════════════════════════════════════════ */
function CTooltip({ active, payload, unit="" }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{background:"var(--bg-card)",border:"1px solid var(--border)",borderRadius:4,padding:"6px 10px",fontFamily:"var(--font-data)",fontSize:10}}>
      {payload.map((p: any,i: number) => (
        <div key={i} style={{color:p.color}}>{p.name}: {p.value}{unit}</div>
      ))}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   DASHBOARD
═══════════════════════════════════════════════════════════════ */
function Dashboard({ devices, onScan }: { devices: typeof DEVICES; onScan: () => void }) {
  const online = devices.filter(d=>d.status==="online").length;
  const offline = devices.filter(d=>d.status==="offline").length;
  const avgLat = Math.round(devices.filter(d=>d.latency>0).reduce((a,d)=>a+d.latency,0)/devices.filter(d=>d.latency>0).length);
  const totalPorts = devices.reduce((a,d)=>a+d.ports.filter(p=>p.s==="open").length,0);
  const bwData = useMemo(()=>genBandwidth(),[]);

  const recentAlerts = [
    { time:"14:32:01", msg:"New device: 192.168.1.60 (unknown-device)", type:"warn" },
    { time:"14:30:45", msg:"Port 3389 (RDP) filtered on 192.168.1.20", type:"info" },
    { time:"14:28:12", msg:"Device offline: 192.168.1.70 (old-laptop)",  type:"err"  },
    { time:"14:15:00", msg:"Scan completed: 18 devices, 47 open ports",   type:"ok"   },
    { time:"13:55:22", msg:"Device online: 192.168.1.30 (iPhone-Thomas)", type:"ok"   },
  ];

  return (
    <div className="page-enter">
      <div className="stat-grid">
        <div className="stat-card green">
          <div className="stat-label">DEVICES FOUND</div>
          <div className="stat-value green">{devices.length}</div>
          <div className="stat-change up">↑ 2 vs last scan</div>
        </div>
        <div className="stat-card cyan">
          <div className="stat-label">ONLINE NOW</div>
          <div className="stat-value cyan">{online}</div>
          <div className="stat-change">{offline} offline</div>
        </div>
        <div className="stat-card purple">
          <div className="stat-label">AVG LATENCY</div>
          <div className="stat-value purple">{avgLat}<span style={{fontSize:14}}>ms</span></div>
          <div className="stat-change">LAN performance</div>
        </div>
        <div className="stat-card orange">
          <div className="stat-label">OPEN PORTS</div>
          <div className="stat-value orange">{totalPorts}</div>
          <div className="stat-change">across all hosts</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">NETWORK TRAFFIC</div>
          <div style={{height:180}}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={bwData} margin={{top:5,right:5,left:-30,bottom:0}}>
                <defs>
                  <linearGradient id="rxGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#00e5ff" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#00e5ff" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="txGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#00ff9d" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#00ff9d" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" tick={false} axisLine={false} tickLine={false}/>
                <YAxis tick={{fill:"#475569",fontSize:9}} axisLine={false} tickLine={false}/>
                <Tooltip content={<CTooltip unit=" Mbps"/>}/>
                <Area type="monotone" dataKey="rx" name="RX" stroke="#00e5ff" fill="url(#rxGrad)" strokeWidth={1.5} dot={false}/>
                <Area type="monotone" dataKey="tx" name="TX" stroke="#00ff9d" fill="url(#txGrad)" strokeWidth={1.5} dot={false}/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div style={{display:"flex",gap:16,marginTop:8}}>
            {[{c:"#00e5ff",l:"RX Download"},{c:"#00ff9d",l:"TX Upload"}].map(x=>(
              <div key={x.l} style={{display:"flex",alignItems:"center",gap:6,fontSize:10,fontFamily:"var(--font-data)",color:"var(--text-3)"}}>
                <div style={{width:20,height:2,background:x.c,borderRadius:1}}/>
                {x.l}
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-title">DEVICE TYPES</div>
          {[
            ["Router/Switch/Modem", devices.filter(d=>["Router","Switch","Modem"].includes(d.type)).length, "#00ff9d"],
            ["Workstation/Laptop",  devices.filter(d=>["Workstation","Laptop"].includes(d.type)).length,   "#00e5ff"],
            ["Server/Virtual/NAS",  devices.filter(d=>["Server","Virtual","NAS"].includes(d.type)).length,  "#a855f7"],
            ["Phone/SmartDevice",   devices.filter(d=>["Phone","SmartDevice"].includes(d.type)).length,      "#f97316"],
            ["IoT / Camera",        devices.filter(d=>["IoT","Camera","SmartTV"].includes(d.type)).length,   "#eab308"],
            ["Other",               devices.filter(d=>["VPN","Printer","Unknown"].includes(d.type)).length,  "#94a3b8"],
          ].map(([label,count,color])=>(
            <div key={label as string} style={{display:"flex",alignItems:"center",gap:10,marginBottom:8}}>
              <div style={{fontSize:10,fontFamily:"var(--font-data)",color:"var(--text-3)",width:140,flexShrink:0}}>{label}</div>
              <div style={{flex:1,background:"rgba(255,255,255,0.04)",borderRadius:2,height:6,overflow:"hidden"}}>
                <div style={{width:`${((count as number)/devices.length)*100}%`,height:"100%",background:color as string,borderRadius:2,transition:"width 1s ease"}}/>
              </div>
              <div style={{fontSize:11,fontFamily:"var(--font-data)",color:color as string,minWidth:20,textAlign:"right"}}>{count}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
            <div className="card-title" style={{marginBottom:0}}>RECENT DEVICES</div>
            <button className="btn btn-primary btn-sm" onClick={onScan}>
              <Icon.Play/> SCAN NOW
            </button>
          </div>
          <table className="device-table">
            <thead>
              <tr><th>IP ADDRESS</th><th>HOSTNAME</th><th>STATUS</th><th>LATENCY</th></tr>
            </thead>
            <tbody>
              {devices.slice(0,8).map(d=>(
                <tr key={d.ip}>
                  <td className="ip-cell">{d.ip}</td>
                  <td className="hostname-cell" style={{fontSize:11}}>{d.hostname||"—"}</td>
                  <td><span className={`status-badge ${d.status}`}><span className="dot"/>{d.status.toUpperCase()}</span></td>
                  <td className={`latency-cell ${d.latency===0?"dead":d.latency<20?"fast":""}`}>
                    {d.status==="offline"?"—":`${d.latency}ms`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card">
          <div className="card-title">SECURITY EVENTS</div>
          <div className="terminal-log">
            {recentAlerts.map((a,i)=>(
              <div key={i}>
                <span className="t-dim">[{a.time}] </span>
                <span className={a.type==="warn"?"t-yellow":a.type==="err"?"t-red":a.type==="info"?"t-cyan":"t-green"}>
                  {a.msg}
                </span>
              </div>
            ))}
            <div><span className="t-dim">[14:10:00] </span><span className="t-green">NetHawk engine initialized — ready</span></div>
            <div><span className="t-dim">[14:09:55] </span><span className="t-dim">Loading OUI vendor database... 28,412 entries</span></div>
            <div><span className="t-dim">[14:09:54] </span><span className="t-dim">OS fingerprint db loaded — 4,200 signatures</span></div>
            <div><span className="t-dim">[14:09:53] </span><span className="t-green">NetHawk v2.4.1 starting on interface eth0</span></div>
          </div>
          <div style={{display:"flex",gap:8,marginTop:12}}>
            {[["JSON","#00ff9d"],["CSV","#00e5ff"],["PDF","#a855f7"]].map(([fmt,c])=>(
              <button key={fmt} className="btn btn-secondary btn-sm" style={{color:c,borderColor:c+"44"}}>
                <Icon.Export/> {fmt}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   IP SCANNER
═══════════════════════════════════════════════════════════════ */
function Scanner({ devices, running, setRunning }: {
  devices: typeof DEVICES;
  setDevices: any;
  running: boolean;
  setRunning: (v: boolean) => void;
}) {
  const [progress, setProgress]   = useState(0);
  const [scanRange, setScanRange] = useState("192.168.1.0/24");
  const [threads, setThreads]     = useState(64);
  const [timeoutMs, setTimeoutMs] = useState(1000);
  const [logLines, setLogLines]   = useState<{msg:string;type:string;id:number}[]>([]);
  const [sortCol, setSortCol]     = useState("ip");
  const [sortDir, setSortDir]     = useState(1);
  const [search, setSearch]       = useState("");
  const [expanded, setExpanded]   = useState<string|null>(null);
  const [found, setFound]         = useState(0);
  const logRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<any>(null);

  const addLog = useCallback((msg: string, type="") => {
    setLogLines(l => [...l.slice(-60), {msg, type, id: Date.now()+Math.random()}]);
  }, []);

  const startScan = useCallback(() => {
    if (running) {
      clearInterval(intervalRef.current);
      setRunning(false);
      setProgress(0);
      setFound(0);
      addLog("⚠ Scan aborted by user", "warn");
      return;
    }
    setRunning(true);
    setProgress(0);
    setFound(0);
    setLogLines([]);
    addLog(`Starting scan: ${scanRange}`, "ok");
    addLog(`Threads: ${threads} · Timeout: ${timeoutMs}ms`, "dim");
    addLog("Initializing scanner engine...", "dim");

    let p = 0;
    let f = 0;

    intervalRef.current = setInterval(() => {
      p += Math.random() * 3 + 1;
      if (p >= 100) {
        p = 100;
        clearInterval(intervalRef.current);
        setRunning(false);
        addLog(`✓ Scan complete — ${f} devices found`, "ok");
      }
      setProgress(Math.min(p, 100));

      if (Math.random() < 0.3) {
        const ip = `192.168.1.${Math.floor(Math.random()*254)+1}`;
        const ms = Math.floor(Math.random()*150)+1;
        f++;
        setFound(prev => prev+1);
        addLog(`✓ FOUND ${ip} — ${ms}ms`, "found");
      } else {
        const ip = `192.168.1.${Math.floor((p/100)*254)}`;
        addLog(`→ Probing ${ip}...`, "dim");
      }
    }, 120);
  }, [running, scanRange, threads, timeoutMs, addLog]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logLines]);

  useEffect(() => () => clearInterval(intervalRef.current), []);

  const sorted = useMemo(() => {
    let list = [...devices];
    if (search) list = list.filter(d =>
      d.ip.includes(search) || d.hostname.toLowerCase().includes(search.toLowerCase()) ||
      d.vendor.toLowerCase().includes(search.toLowerCase()) || d.type.toLowerCase().includes(search.toLowerCase())
    );
    list.sort((a,b) => {
      if (sortCol==="ip") {
        const ai = a.ip.split(".").reduce((x,n)=>x*256+parseInt(n),0);
        const bi = b.ip.split(".").reduce((x,n)=>x*256+parseInt(n),0);
        return (ai-bi)*sortDir;
      }
      if (sortCol==="latency") return (a.latency-b.latency)*sortDir;
      return ((a as any)[sortCol]||"").localeCompare((b as any)[sortCol]||"")*sortDir;
    });
    return list;
  }, [devices, sortCol, sortDir, search]);

  const sort = (col: string) => {
    if (sortCol===col) setSortDir((d: number) => -d);
    else { setSortCol(col); setSortDir(1); }
  };

  return (
    <div className="page-enter">
      <div className="card" style={{marginBottom:14}}>
        <div className="card-title">SCAN CONFIGURATION</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:14,marginBottom:14}}>
          <div>
            <div className="input-label">TARGET RANGE / CIDR</div>
            <input className="input-field" style={{width:"100%"}} value={scanRange}
              onChange={e=>setScanRange(e.target.value)} placeholder="e.g. 192.168.1.0/24"/>
          </div>
          <div>
            <div className="input-label">THREADS — {threads}</div>
            <div className="range-wrap">
              <input type="range" min="1" max="512" value={threads}
                onChange={e=>setThreads(+e.target.value)} className="range-input"/>
              <span className="range-val">{threads}</span>
            </div>
          </div>
          <div>
            <div className="input-label">TIMEOUT (ms) — {timeoutMs}</div>
            <div className="range-wrap">
              <input type="range" min="100" max="5000" step="100" value={timeoutMs}
                onChange={e=>setTimeoutMs(+e.target.value)} className="range-input"/>
              <span className="range-val">{timeoutMs}</span>
            </div>
          </div>
        </div>
        <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
          <button className={`btn btn-primary ${running?"running":""}`} onClick={startScan}>
            {running ? <><Icon.Stop/> STOP SCAN</> : <><Icon.Play/> START SCAN</>}
          </button>
          <button className="btn btn-secondary btn-sm"><Icon.Settings/> PROFILES</button>
          <div style={{flex:1}}/>
          <div className="export-bar">
            {["JSON","CSV","TXT"].map(f=>(
              <button key={f} className="btn btn-secondary btn-sm"><Icon.Export/> {f}</button>
            ))}
          </div>
        </div>
      </div>

      {(running || progress > 0) && (
        <div className="card" style={{marginBottom:14}}>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}>
            <div className="card-title" style={{marginBottom:0}}>
              {running ? "SCANNING IN PROGRESS..." : "SCAN COMPLETE"}
            </div>
            <div style={{fontFamily:"var(--font-data)",fontSize:11,color:running?"var(--green)":"var(--text-2)"}}>
              {Math.round(progress)}%
            </div>
          </div>
          <div className="progress-wrap">
            <div className="progress-bar" style={{width:`${progress}%`}}/>
          </div>
          <div className="scan-stats-row">
            <span>Hosts scanned: <span className="hi">{Math.round((progress/100)*254)}/254</span></span>
            <span>Found: <span className="hi">{found}</span></span>
            <span>Threads: <span>{threads}</span></span>
            <span>Range: <span>{scanRange}</span></span>
          </div>
          <div className="terminal-log" style={{height:100,marginTop:12}} ref={logRef}>
            {logLines.map(l=>(
              <div key={l.id} className={`scan-line-item ${l.type}`}>{l.msg}</div>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14,flexWrap:"wrap",gap:10}}>
          <div className="card-title" style={{marginBottom:0}}>
            DISCOVERED DEVICES — <span style={{color:"var(--green)"}}>{sorted.length}</span>
          </div>
          <div className="search-wrap">
            <span className="search-icon"><Icon.Search/></span>
            <input className="search-field" placeholder="Filter IP, hostname, vendor..." value={search} onChange={e=>setSearch(e.target.value)}/>
          </div>
        </div>

        <div style={{overflowX:"auto"}}>
          <table className="device-table">
            <thead>
              <tr>
                <th style={{width:30}}/>
                {[["ip","IP ADDRESS"],["hostname","HOSTNAME"],["vendor","VENDOR"],["type","TYPE"],["os","OS"],["status","STATUS"],["latency","LATENCY"],["ports","OPEN PORTS"]].map(([col,label])=>(
                  <th key={col} onClick={()=>sort(col)}>
                    <span style={{display:"flex",alignItems:"center",gap:4}}>
                      {label} {sortCol===col && (sortDir===1?"↑":"↓")}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sorted.map(d=>(
                <>
                  <tr key={d.ip} className={expanded===d.ip?"expanded":""}>
                    <td>
                      <button className={`expand-btn ${expanded===d.ip?"expanded":""}`}
                        onClick={()=>setExpanded(expanded===d.ip?null:d.ip)}>›</button>
                    </td>
                    <td className="ip-cell">{d.ip}</td>
                    <td className="hostname-cell">{d.hostname||<span style={{color:"var(--text-3)"}}>—</span>}</td>
                    <td className="vendor-cell">{d.vendor}</td>
                    <td style={{fontSize:10,color:"var(--text-2)"}}>{d.type}</td>
                    <td><span className="os-badge">{d.os}</span></td>
                    <td><span className={`status-badge ${d.status}`}><span className="dot"/>{d.status.toUpperCase()}</span></td>
                    <td className={`latency-cell ${d.latency===0?"dead":d.latency<20?"fast":d.latency<80?"slow":""}`}>
                      {d.status==="offline"?"TIMEOUT":`${d.latency}ms`}
                    </td>
                    <td>
                      <div className="ports-mini">
                        {d.ports.filter(p=>p.s!=="closed").slice(0,4).map(p=>(
                          <span key={p.n} className={`port-chip ${p.s}`}>{p.n}</span>
                        ))}
                        {d.ports.length>4&&<span style={{fontSize:9,color:"var(--text-3)"}}>+{d.ports.length-4}</span>}
                      </div>
                    </td>
                  </tr>
                  {expanded===d.ip && (
                    <tr key={d.ip+"-detail"}>
                      <td colSpan={9} style={{padding:0}}>
                        <div className="device-detail">
                          <div>
                            <div className="detail-section-title">NETWORK INFO</div>
                            <div className="detail-kv">
                              {[["IP Address",d.ip],["Hostname",d.hostname||"—"],["MAC Address",d.mac],["Vendor",d.vendor],["Device Type",d.type]].map(([k,v])=>(
                                <div key={k} className="detail-row"><span className="k">{k}</span><span className="v">{v}</span></div>
                              ))}
                            </div>
                          </div>
                          <div>
                            <div className="detail-section-title">SYSTEM INFO</div>
                            <div className="detail-kv">
                              {[["OS",d.os],["Latency",d.status==="offline"?"OFFLINE":`${d.latency}ms`],["Status",d.status.toUpperCase()],["Tags",d.tags.join(", ")||"none"]].map(([k,v])=>(
                                <div key={k} className="detail-row"><span className="k">{k}</span><span className="v">{v}</span></div>
                              ))}
                            </div>
                          </div>
                          <div>
                            <div className="detail-section-title">OPEN PORTS ({d.ports.length})</div>
                            <div className="ports-detail">
                              {d.ports.length===0
                                ? <span style={{fontSize:11,color:"var(--text-3)"}}>No ports detected</span>
                                : d.ports.map(p=>(
                                    <div key={p.n} className={`port-detail-chip ${p.s}`}>
                                      <strong>{p.n}</strong> {p.svc}
                                    </div>
                                  ))
                              }
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   PORT SCANNER
═══════════════════════════════════════════════════════════════ */
function PortScanner() {
  const [target, setTarget]     = useState("192.168.1.1");
  const [mode, setMode]         = useState("common");
  const [portRange, setPortRange] = useState("1-1024");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults]   = useState<any[]>([]);
  const intervalRef = useRef<any>(null);

  const COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,27017];

  const startPortScan = () => {
    if (scanning) {
      clearInterval(intervalRef.current);
      setScanning(false);
      return;
    }
    setScanning(true);
    setProgress(0);
    setResults([]);

    const ports = mode==="common" ? COMMON_PORTS :
      mode==="full" ? Array.from({length:65535},(_,i)=>i+1) :
      portRange.split("-").length===2 ? Array.from({length:parseInt(portRange.split("-")[1])-parseInt(portRange.split("-")[0])+1},(_,i)=>i+parseInt(portRange.split("-")[0])) :
      COMMON_PORTS;

    const total = ports.length;
    let scanned = 0;

    intervalRef.current = setInterval(() => {
      const batch = Math.min(Math.floor(Math.random()*5)+1, total-scanned);
      for (let i=0;i<batch;i++) {
        const port = ports[scanned+i];
        if (!port) continue;
        const r = Math.random();
        const state = r < 0.15 ? "open" : r < 0.25 ? "filtered" : "closed";
        setResults((prev: any[]) => [...prev, {
          port, state,
          service: SERVICE_MAP[port] || "",
          latency: state==="open" ? Math.floor(Math.random()*50)+1 : null,
        }]);
      }
      scanned += batch;
      setProgress(Math.min((scanned/total)*100, 100));
      if (scanned >= total) {
        clearInterval(intervalRef.current);
        setScanning(false);
      }
    }, 50);
  };

  useEffect(() => () => clearInterval(intervalRef.current), []);

  const open = results.filter(r=>r.state==="open");
  const filtered = results.filter(r=>r.state==="filtered");

  return (
    <div className="page-enter">
      <div className="card" style={{marginBottom:14}}>
        <div className="card-title">PORT SCAN CONFIGURATION</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:14,marginBottom:14}}>
          <div>
            <div className="input-label">TARGET HOST</div>
            <input className="input-field" style={{width:"100%"}} value={target}
              onChange={e=>setTarget(e.target.value)} placeholder="IP or hostname"/>
          </div>
          <div>
            <div className="input-label">SCAN MODE</div>
            <select className="select-field" style={{width:"100%"}} value={mode} onChange={e=>setMode(e.target.value)}>
              <option value="common">Common Ports (Top 20)</option>
              <option value="range">Custom Range</option>
              <option value="full">Full Scan (1-65535)</option>
            </select>
          </div>
          <div>
            <div className="input-label">PORT RANGE (if custom)</div>
            <input className="input-field" value={portRange}
              onChange={e=>setPortRange(e.target.value)} placeholder="1-1024" disabled={mode!=="range"}
              style={{width:"100%",opacity:mode==="range"?1:0.4}}/>
          </div>
        </div>
        <div style={{display:"flex",gap:10,alignItems:"center"}}>
          <button className={`btn btn-primary ${scanning?"running":""}`} onClick={startPortScan}>
            {scanning ? <><Icon.Stop/> ABORT</> : <><Icon.Play/> SCAN PORTS</>}
          </button>
          <div style={{flex:1}}/>
          {results.length > 0 && (
            <div style={{fontFamily:"var(--font-data)",fontSize:11,color:"var(--text-3)",display:"flex",gap:16}}>
              <span>Open: <span style={{color:"var(--cyan)"}}>{open.length}</span></span>
              <span>Filtered: <span style={{color:"var(--yellow)"}}>{filtered.length}</span></span>
              <span>Scanned: <span style={{color:"var(--text-2)"}}>{results.length}</span></span>
            </div>
          )}
        </div>
      </div>

      {(scanning || progress > 0) && (
        <div className="card" style={{marginBottom:14}}>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}>
            <div className="card-title" style={{marginBottom:0}}>
              {scanning ? `SCANNING ${target}...` : "SCAN COMPLETE"}
            </div>
            <div style={{fontFamily:"var(--font-data)",fontSize:11,color:"var(--green)"}}>{Math.round(progress)}%</div>
          </div>
          <div className="progress-wrap"><div className="progress-bar" style={{width:`${progress}%`}}/></div>
        </div>
      )}

      {open.length > 0 && (
        <div className="card" style={{marginBottom:14}}>
          <div className="card-title">OPEN PORTS — {open.length} FOUND</div>
          <div className="port-result-grid">
            {open.map((r:any)=>(
              <div key={r.port} className={`port-result-tile ${r.state}`}>
                <div className="port-num">{r.port}</div>
                <div className={`port-state ${r.state}`}>{r.state.toUpperCase()}</div>
                <div className="port-service">{r.service||"unknown"}</div>
                {r.latency && <div style={{fontSize:9,color:"var(--text-3)",marginTop:2}}>{r.latency}ms</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {filtered.length > 0 && (
        <div className="card" style={{marginBottom:14}}>
          <div className="card-title">FILTERED PORTS — {filtered.length}</div>
          <div className="port-result-grid">
            {filtered.slice(0,24).map((r:any)=>(
              <div key={r.port} className={`port-result-tile ${r.state}`}>
                <div className="port-num">{r.port}</div>
                <div className={`port-state ${r.state}`}>FILTERED</div>
                <div className="port-service">{r.service||"—"}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   LIVE MONITOR
═══════════════════════════════════════════════════════════════ */
function LiveMonitor({ devices }: { devices: typeof DEVICES }) {
  const [history, setHistory] = useState<Record<string,any[]>>(() =>
    Object.fromEntries(devices.map(d=>[d.ip, genPingHistory(d.latency, d.status==="online")]))
  );

  useEffect(() => {
    const id = setInterval(() => {
      setHistory(h => {
        const next = {...h};
        devices.filter(d=>d.status==="online").forEach(d => {
          const prev = next[d.ip] || [];
          const newPoint = { t: prev.length, ms: Math.max(1, d.latency + Math.round((Math.random()-0.5)*d.latency*0.5)) };
          next[d.ip] = [...prev.slice(-29), newPoint];
        });
        return next;
      });
    }, 1500);
    return () => clearInterval(id);
  }, [devices]);

  const online = devices.filter(d=>d.status==="online");

  return (
    <div className="page-enter">
      <div style={{display:"flex",gap:10,marginBottom:14,flexWrap:"wrap",alignItems:"center"}}>
        <div style={{fontFamily:"var(--font-data)",fontSize:11,color:"var(--text-2)"}}>
          LIVE MONITORING — <span style={{color:"var(--green)"}}>{online.length} ACTIVE HOSTS</span>
        </div>
        <div style={{flex:1}}/>
        <div style={{display:"flex",alignItems:"center",gap:6,fontSize:10,fontFamily:"var(--font-data)",color:"var(--green)"}}>
          <span className="status-dot"/>
          STREAMING LIVE
        </div>
      </div>

      <div className="monitor-grid">
        {online.slice(0,16).map(d=>{
          const hist = history[d.ip] || [];
          const latest = hist[hist.length-1]?.ms ?? d.latency;
          return (
            <div key={d.ip} className={`monitor-card ${d.status}`}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                <div>
                  <div className="monitor-card-ip">{d.ip}</div>
                  <div className="monitor-card-name">{d.hostname||d.type}</div>
                </div>
                <span className="status-badge online" style={{fontSize:8}}><span className="dot"/>LIVE</span>
              </div>
              <div className="mini-chart-wrap">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={hist} margin={{top:2,right:0,left:0,bottom:0}}>
                    <Line type="monotone" dataKey="ms" stroke="#00ff9d" strokeWidth={1.5}
                      dot={false} isAnimationActive={false}/>
                    <Tooltip content={<CTooltip unit="ms"/>}/>
                  </LineChart>
                </ResponsiveContainer>
              </div>
              <div className="monitor-latency">
                <span style={{color:"var(--green)"}}>{latest}ms</span>
                <span style={{marginLeft:8,color:"var(--text-3)"}}>{d.type}</span>
              </div>
            </div>
          );
        })}
      </div>

      {devices.filter(d=>d.status==="offline").length > 0 && (
        <div style={{marginTop:20}}>
          <div className="card-title" style={{marginBottom:12}}>OFFLINE HOSTS</div>
          <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
            {devices.filter(d=>d.status==="offline").map(d=>(
              <div key={d.ip} className="monitor-card offline" style={{minWidth:160}}>
                <div className="monitor-card-ip">{d.ip}</div>
                <div className="monitor-card-name">{d.hostname||d.type}</div>
                <span className="status-badge offline" style={{fontSize:8}}><span className="dot"/>OFFLINE</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   NETWORK MAP (D3 Force Simulation)
═══════════════════════════════════════════════════════════════ */
function NetworkMap({ devices }: { devices: typeof DEVICES }) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current) return;
    const el = svgRef.current;
    const W = el.clientWidth || 700, H = el.clientHeight || 500;

    d3.select(el).selectAll("*").remove();

    const svg = d3.select(el);
    const g   = svg.append("g");

    svg.call((d3.zoom() as any).scaleExtent([0.3,3])
      .on("zoom", (e: any) => g.attr("transform", e.transform)));

    const online = devices.filter(d=>d.status==="online");
    const gateway = online.find(d=>d.type==="Router") || online[0];

    const nodes: any[] = online.map(d=>({
      id: d.ip, label: d.hostname||d.type, type: d.type,
      latency: d.latency, ports: d.ports.filter(p=>p.s==="open").length,
      isGateway: d===gateway,
    }));

    const links: any[] = online
      .filter(d=>d!==gateway && d.ip!==gateway.ip)
      .map(d=>({ source: gateway.ip, target: d.ip, latency: d.latency }));

    const color = (type: string) => ({
      "Router":"#00ff9d","Switch":"#00ff9d","Modem":"#00ff9d",
      "Server":"#a855f7","Virtual":"#a855f7","NAS":"#a855f7",
      "Laptop":"#00e5ff","Workstation":"#00e5ff","Phone":"#f97316",
      "IoT":"#eab308","Camera":"#eab308","SmartTV":"#eab308",
      "Printer":"#94a3b8","Unknown":"#ef4444","VPN":"#f97316",
    } as any)[type]||"#64748b";

    const sim = d3.forceSimulation(nodes)
      .force("link",    d3.forceLink(links).id((d:any)=>d.id).distance(80).strength(0.5))
      .force("charge",  d3.forceManyBody().strength(-300))
      .force("center",  d3.forceCenter(W/2, H/2))
      .force("collision", d3.forceCollide(35));

    const link = g.append("g").selectAll("line")
      .data(links).join("line")
      .attr("stroke","#00ff9d")
      .attr("stroke-opacity",0.2)
      .attr("stroke-width",1)
      .attr("stroke-dasharray","4 2")
      .attr("class","map-link");

    const node = g.append("g").selectAll("g")
      .data(nodes).join("g")
      .attr("class","map-node")
      .style("cursor","pointer")
      .call((d3.drag() as any)
        .on("start", (e: any,d: any) => { if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
        .on("drag",  (e: any,d: any) => { d.fx=e.x; d.fy=e.y; })
        .on("end",   (e: any,d: any) => { if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }));

    node.append("circle")
      .attr("r", (d:any) => d.isGateway?30:20)
      .attr("fill","none")
      .attr("stroke", (d:any)=>color(d.type))
      .attr("stroke-opacity",0.2)
      .attr("stroke-width",6);

    node.append("circle")
      .attr("r", (d:any)=>d.isGateway?22:15)
      .attr("fill", (d:any)=>`${color(d.type)}22`)
      .attr("stroke", (d:any)=>color(d.type))
      .attr("stroke-width",1.5);

    node.append("text")
      .attr("text-anchor","middle")
      .attr("dominant-baseline","central")
      .attr("fill", (d:any)=>color(d.type))
      .attr("font-family","JetBrains Mono, monospace")
      .attr("font-size", (d:any)=>d.isGateway?12:9)
      .attr("font-weight","600")
      .text((d:any)=>d.type.slice(0,2).toUpperCase());

    node.append("text")
      .attr("text-anchor","middle")
      .attr("y", (d:any)=>d.isGateway?36:28)
      .attr("fill","#94a3b8")
      .attr("font-family","JetBrains Mono, monospace")
      .attr("font-size",9)
      .text((d:any)=>d.label.length>14?d.id:d.label);

    const linkLabel = g.append("g").selectAll("text")
      .data(links).join("text")
      .attr("text-anchor","middle")
      .attr("fill","#475569")
      .attr("font-family","JetBrains Mono, monospace")
      .attr("font-size",8)
      .text((d:any)=>`${d.latency}ms`);

    sim.on("tick", ()=>{
      link
        .attr("x1",(d:any)=>d.source.x).attr("y1",(d:any)=>d.source.y)
        .attr("x2",(d:any)=>d.target.x).attr("y2",(d:any)=>d.target.y);
      node.attr("transform",(d:any)=>`translate(${d.x},${d.y})`);
      linkLabel
        .attr("x",(d:any)=>(d.source.x+d.target.x)/2)
        .attr("y",(d:any)=>(d.source.y+d.target.y)/2-5);
    });

    return () => { sim.stop(); };
  }, [devices]);

  return (
    <div className="page-enter">
      <div style={{display:"flex",gap:10,marginBottom:14,alignItems:"center",flexWrap:"wrap"}}>
        <div style={{fontFamily:"var(--font-data)",fontSize:11,color:"var(--text-2)"}}>
          NETWORK TOPOLOGY MAP — drag nodes, scroll to zoom
        </div>
        <div style={{flex:1}}/>
        <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
          {[["Router","#00ff9d"],["Server","#a855f7"],["PC/Laptop","#00e5ff"],["Phone","#f97316"],["IoT","#eab308"],["Unknown","#ef4444"]].map(([t,c])=>(
            <div key={t} style={{display:"flex",alignItems:"center",gap:5,fontSize:10,fontFamily:"var(--font-data)"}}>
              <div style={{width:8,height:8,borderRadius:"50%",background:c,boxShadow:`0 0 4px ${c}`}}/>
              <span style={{color:"var(--text-3)"}}>{t}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="card" style={{padding:0,overflow:"hidden",height:500}}>
        <svg ref={svgRef} id="network-map-svg" style={{width:"100%",height:"100%",background:"var(--bg-void)"}}/>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   HISTORY
═══════════════════════════════════════════════════════════════ */
function History() {
  const historyData = useMemo(() => HISTORY, []);
  const chartData = historyData.map(h=>({name:h.time.slice(11,16), found:h.found, ports:h.ports})).reverse();

  return (
    <div className="page-enter">
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginBottom:14}}>
        <div className="card">
          <div className="card-title">DEVICES FOUND PER SCAN</div>
          <div style={{height:160}}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{top:5,right:5,left:-30,bottom:0}}>
                <XAxis dataKey="name" tick={{fill:"#475569",fontSize:9}} axisLine={false} tickLine={false}/>
                <YAxis tick={{fill:"#475569",fontSize:9}} axisLine={false} tickLine={false}/>
                <Tooltip content={<CTooltip/>}/>
                <Bar dataKey="found" name="Devices" fill="#00ff9d" fillOpacity={0.8} radius={[2,2,0,0]}/>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card">
          <div className="card-title">OPEN PORTS DETECTED</div>
          <div style={{height:160}}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{top:5,right:5,left:-30,bottom:0}}>
                <defs>
                  <linearGradient id="pG" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#a855f7" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#a855f7" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" tick={{fill:"#475569",fontSize:9}} axisLine={false} tickLine={false}/>
                <YAxis tick={{fill:"#475569",fontSize:9}} axisLine={false} tickLine={false}/>
                <Tooltip content={<CTooltip/>}/>
                <Area type="monotone" dataKey="ports" name="Ports" stroke="#a855f7" fill="url(#pG)" strokeWidth={1.5} dot={false}/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="card">
        <div style={{display:"flex",justifyContent:"space-between",marginBottom:12,alignItems:"center"}}>
          <div className="card-title" style={{marginBottom:0}}>SCAN HISTORY — {historyData.length} RECORDS</div>
          <div style={{display:"flex",gap:8}}>
            {["JSON","CSV"].map(f=><button key={f} className="btn btn-secondary btn-sm"><Icon.Export/> {f}</button>)}
          </div>
        </div>
        <div>
          <div className="history-row" style={{opacity:0.5,borderBottom:"1px solid var(--border-dim)"}}>
            <span className="history-time">TIMESTAMP</span>
            <span className="history-range">RANGE</span>
            <span className="history-found">DEVICES</span>
            <span style={{fontFamily:"var(--font-data)",fontSize:10,color:"var(--text-3)",minWidth:80}}>ONLINE</span>
            <span style={{fontFamily:"var(--font-data)",fontSize:10,color:"var(--text-3)",minWidth:60}}>PORTS</span>
            <span className="history-duration">DURATION</span>
          </div>
          {historyData.map(h=>(
            <div key={h.id} className="history-row">
              <span className="history-time">{h.time}</span>
              <span className="history-range">{h.range}</span>
              <span className="history-found">{h.found} found</span>
              <span style={{fontFamily:"var(--font-data)",fontSize:11,color:"var(--green)",minWidth:80}}>{h.online} online</span>
              <span style={{fontFamily:"var(--font-data)",fontSize:11,color:"var(--purple)",minWidth:60}}>{h.ports}</span>
              <span className="history-duration" style={{color:"var(--text-2)"}}>{h.duration}</span>
              <button className="btn btn-secondary btn-sm" style={{marginLeft:"auto"}}><Icon.Eye/> VIEW</button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   SETTINGS
═══════════════════════════════════════════════════════════════ */
function Settings() {
  return (
    <div className="page-enter">
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
        {[
          {title:"SCAN DEFAULTS", fields:[
            {label:"Default Thread Count",type:"range",min:1,max:512,val:64},
            {label:"Default Timeout (ms)",type:"range",min:100,max:5000,step:100,val:1000},
            {label:"Default Interface",type:"select",opts:["eth0","wlan0","en0","Auto"]},
          ]},
          {title:"NOTIFICATIONS", fields:[
            {label:"New Device Detected",type:"toggle",val:true},
            {label:"Device Goes Offline",type:"toggle",val:true},
            {label:"New Port Opened",type:"toggle",val:false},
            {label:"Suspicious Activity",type:"toggle",val:true},
          ]},
          {title:"AUTO-REFRESH", fields:[
            {label:"Enable Auto-Scan",type:"toggle",val:true},
            {label:"Refresh Interval (sec)",type:"range",min:10,max:300,step:10,val:30},
          ]},
          {title:"ABOUT NETHAWK", fields:[]},
        ].map(section=>(
          <div key={section.title} className="card">
            <div className="card-title">{section.title}</div>
            <div style={{display:"flex",flexDirection:"column",gap:14}}>
              {section.fields.map((f,i)=>(
                <div key={i}>
                  <div className="input-label">{f.label}</div>
                  {f.type==="range" && (
                    <div className="range-wrap">
                      <input type="range" className="range-input" min={f.min ?? 1} max={f.max ?? 100} step={String((f as any).step || 1)} defaultValue={String(f.val ?? 50)}/>
                      <span className="range-val">{f.val}</span>
                    </div>
                  )}
                  {f.type==="toggle" && (
                    <div style={{display:"flex",alignItems:"center",gap:10}}>
                      <div style={{
                        width:36,height:20,background:f.val?"rgba(0,255,157,0.2)":"rgba(255,255,255,0.06)",
                        border:`1px solid ${f.val?"var(--green)":"var(--border-dim)"}`,
                        borderRadius:10,position:"relative",cursor:"pointer",transition:"all 0.2s"
                      }}>
                        <div style={{
                          width:14,height:14,background:f.val?"var(--green)":"var(--text-3)",
                          borderRadius:"50%",position:"absolute",top:2,left:f.val?18:2,transition:"all 0.2s"
                        }}/>
                      </div>
                      <span style={{fontSize:11,fontFamily:"var(--font-data)",color:f.val?"var(--green)":"var(--text-3)"}}>
                        {f.val?"ENABLED":"DISABLED"}
                      </span>
                    </div>
                  )}
                  {f.type==="select" && (
                    <select className="select-field" style={{width:"100%"}} defaultValue={(f as any).opts[0]}>
                      {(f as any).opts.map((o: string)=><option key={o}>{o}</option>)}
                    </select>
                  )}
                </div>
              ))}
              {section.title==="ABOUT NETHAWK" && (
                <div style={{fontFamily:"var(--font-data)",fontSize:11,color:"var(--text-3)",lineHeight:1.8}}>
                  <div><span style={{color:"var(--text-2)"}}>Version:</span> 2.4.1 (2024-01-15)</div>
                  <div><span style={{color:"var(--text-2)"}}>Engine:</span> NetHawk Scanner v3</div>
                  <div><span style={{color:"var(--text-2)"}}>OUI Database:</span> 28,412 entries</div>
                  <div><span style={{color:"var(--text-2)"}}>OS Fingerprints:</span> 4,200 signatures</div>
                  <div style={{marginTop:8}}>
                    <div><span style={{color:"var(--text-2)"}}>CFCIA Module:</span> v1.0.0</div>
                    <div><span style={{color:"var(--text-2)"}}>CF IP Ranges:</span> 15 subnets (AS13335)</div>
                  </div>
                  <div style={{marginTop:12}}>
                    <div style={{color:"var(--green)",fontSize:10,letterSpacing:1}}>NETHAWK PROFESSIONAL</div>
                    <div style={{color:"var(--text-3)",fontSize:10,marginTop:2}}>© 2024 NetHawk Security Labs</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   ROOT APP
═══════════════════════════════════════════════════════════════ */
const TAB_TITLES: Record<string,string> = {
  dashboard:"DASHBOARD", scanner:"IP SCANNER", ports:"PORT SCANNER",
  monitor:"LIVE MONITOR", map:"NETWORK MAP", history:"SCAN HISTORY",
  settings:"SETTINGS", cfcia:"CF CLEAN IP ATTACHER",
};

const TAB_CYAN = new Set(["cfcia"]);

export default function NetHawk() {
  const [activeTab, setActiveTab]       = useState("dashboard");
  const [devices]                       = useState(DEVICES);
  const [scanRunning, setScanRunning]   = useState(false);

  const handleNavScan = () => { setActiveTab("scanner"); };

  const title   = TAB_TITLES[activeTab] || "";
  const isCyan  = TAB_CYAN.has(activeTab);

  return (
    <>
      <style>{CSS}</style>
      <div className="nethawk-app">
        <Sidebar
          active={activeTab}
          setActive={setActiveTab}
          scanRunning={scanRunning}
          deviceCount={devices.filter(d=>d.status==="online").length}
        />
        <div className="main-content">
          <div className="topbar">
            <div className="topbar-title">
              NETHAWK <span className={isCyan?"cyan":""}>›</span> {title}
            </div>
            <div className="topbar-spacer"/>
            <div className="topbar-badge">192.168.1.0/24</div>
            <div className="topbar-badge" style={{color:"var(--green)",borderColor:"var(--border)"}}>
              <span className="status-dot" style={{width:5,height:5,marginRight:5}}/>
              CONNECTED
            </div>
          </div>
          <div className="page-scroll">
            {activeTab==="dashboard" && <Dashboard devices={devices} onScan={handleNavScan}/>}
            {activeTab==="scanner"   && <Scanner   devices={devices} setDevices={()=>{}} running={scanRunning} setRunning={setScanRunning}/>}
            {activeTab==="ports"     && <PortScanner/>}
            {activeTab==="monitor"   && <LiveMonitor devices={devices}/>}
            {activeTab==="map"       && <NetworkMap  devices={devices}/>}
            {activeTab==="history"   && <History/>}
            {activeTab==="settings"  && <Settings/>}
            {activeTab==="cfcia"     && <CFCIA/>}
          </div>
        </div>
      </div>
    </>
  );
}
