import React, { createContext, useContext, useMemo, useState } from 'react';

const PcapAnalysisContext = createContext(null);

const API_URL = import.meta.env.VITE_API_URL !== undefined
  ? `${import.meta.env.VITE_API_URL}/api/world-model/risk`
  : '/api/world-model/risk';

const SERVER_PORTS = new Set([80, 443, 22, 21, 25, 53, 8080, 8443]);
const DATABASE_PORTS = new Set([3306, 5432, 1433, 1521, 27017, 6379, 9200]);

export function buildPcapTopologyGraph(attribution) {
  const flows = Array.isArray(attribution?.top_flows) ? attribution.top_flows : [];
  if (!flows.length) return null;
  const ports = new Map();
  flows.forEach((flow) => {
    if (!flow?.dst_ip) return;
    const seen = ports.get(flow.dst_ip) || new Set();
    if (Number.isFinite(Number(flow.dst_port))) seen.add(Number(flow.dst_port));
    ports.set(flow.dst_ip, seen);
  });
  const flagged = new Set();
  const compromised = new Set();
  const scores = new Map();
  flows.forEach((flow) => {
    if (!flow?.src_ip || !flow?.dst_ip) return;
    const score = Number(flow.evidence_score) || 0;
    [flow.src_ip, flow.dst_ip].forEach((ip) => scores.set(ip, Math.max(scores.get(ip) || 0, score)));
    if (flow.flagged) {
      flagged.add(flow.src_ip); flagged.add(flow.dst_ip);
      if (score >= 3) { compromised.add(flow.src_ip); compromised.add(flow.dst_ip); }
    }
  });
  const forecast = new Set();
  flows.filter((flow) => flagged.has(flow?.src_ip) && !flagged.has(flow?.dst_ip))
    .sort((a, b) => (Number(b.packet_count) || 0) - (Number(a.packet_count) || 0))
    .slice(0, 3).forEach((flow) => forecast.add(flow.dst_ip));
  const nodeIds = new Set();
  flows.forEach((flow) => { if (flow?.src_ip) nodeIds.add(flow.src_ip); if (flow?.dst_ip) nodeIds.add(flow.dst_ip); });
  const nodes = [...nodeIds].map((ip) => {
    const seen = ports.get(ip) || new Set();
    const type = [...seen].some((port) => DATABASE_PORTS.has(port)) ? 'database' : [...seen].some((port) => SERVER_PORTS.has(port)) ? 'server' : ip.endsWith('.1') || ip.endsWith('.254') ? 'gateway' : 'endpoint';
    return { id: ip, ip, type, state: compromised.has(ip) ? 'compromised' : flagged.has(ip) ? 'suspicious' : forecast.has(ip) ? 'target' : undefined, risk_score: Math.min(100, Math.round((scores.get(ip) || 0) * 20)) };
  });
  return {
    nodes,
    edges: flows.filter((flow) => flow?.src_ip && flow?.dst_ip).map((flow, index) => ({ id: `${flow.src_ip}-${flow.dst_ip}-${index}`, source: flow.src_ip, target: flow.dst_ip, protocol: flow.protocol, is_attack_path: Boolean(flow.flagged), is_forecasted_path: !flow.flagged && forecast.has(flow.dst_ip) })),
    attack_path_node_ids: [...flagged],
    forecasted_path_node_ids: [...forecast],
    high_risk_nodes_count: nodes.filter((node) => node.state === 'compromised' || node.state === 'suspicious').length,
  };
}

export function PcapAnalysisProvider({ children }) {
  const [analysis, setAnalysis] = useState(null);
  const [fileName, setFileName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function uploadPcap(file) {
    if (!file) return;
    setLoading(true);
    setError('');
    try {
      const formData = new FormData();
      formData.append('file', file);
      const response = await fetch(API_URL, { method: 'POST', body: formData });
      const data = await response.json().catch(() => null);
      if (!response.ok || !data?.success) {
        throw new Error(data?.detail || `Upload failed with HTTP ${response.status}.`);
      }
      setAnalysis(data);
      setFileName(file.name);
    } catch (uploadError) {
      setError(uploadError.message || 'Unable to analyze this PCAP.');
    } finally {
      setLoading(false);
    }
  }

  function clearPcap() {
    setAnalysis(null);
    setFileName('');
    setError('');
  }

  const value = useMemo(() => ({ analysis, fileName, loading, error, uploadPcap, clearPcap }), [analysis, fileName, loading, error]);
  return <PcapAnalysisContext.Provider value={value}>{children}</PcapAnalysisContext.Provider>;
}

export function usePcapAnalysis() {
  const context = useContext(PcapAnalysisContext);
  if (!context) throw new Error('usePcapAnalysis must be used inside PcapAnalysisProvider');
  return context;
}
