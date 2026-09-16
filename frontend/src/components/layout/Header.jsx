import React from 'react';
import { Menu, Clock, Radio, Upload, X } from 'lucide-react';
import RefreshButton from '../common/RefreshButton';
import { usePcapAnalysis } from '../../context/PcapAnalysisContext';

export default function Header({
  onToggleSidebar,
  onRefresh,
  refreshing = false,
  lastUpdated,
  activeScenario,
}) {
  const { fileName, loading, error, uploadPcap, clearPcap } = usePcapAnalysis();

  const handlePcapChange = (event) => {
    const file = event.target.files?.[0];
    if (file) uploadPcap(file);
    event.target.value = '';
  };

  return (
    <header className="sticky top-0 z-30 h-16 border-b border-white/[0.06] bg-[#171310]">
      <div className="h-full px-4 md:px-8 flex items-center justify-between">

        {/* LEFT */}
        <div className="flex items-center gap-4">

          {/* Mobile menu */}
          <button
            onClick={onToggleSidebar}
            className="lg:hidden w-9 h-9 rounded-lg flex items-center justify-center text-[#c9beae] border border-white/[0.08] hover:bg-white/[0.06] hover:text-white transition-colors"
            aria-label="Open navigation"
          >
            <Menu className="w-4 h-4" />
          </button>

          {/* System indicator */}
          <div className="hidden sm:flex items-center gap-2.5 px-3.5 py-2 rounded-lg bg-white/[0.04]">
            <span className="w-2 h-2 rounded-full bg-[#65a30d]" />

            <div className="flex flex-col leading-none">
              <span className="text-[10px] uppercase tracking-wider text-[#8a7d6c] font-medium">
                AI Engine
              </span>
              <span className="mt-1 text-[11px] font-semibold text-white">
                CTU13 LSTM Online
              </span>
            </div>
          </div>

          {/* Scenario */}
          {activeScenario && activeScenario !== 'default' && (
            <div className="hidden md:flex items-center gap-2">
              <div className="w-px h-5 bg-white/[0.08]" />
              <span className="text-[10px] uppercase tracking-wider text-[#8a7d6c] font-medium">
                Scenario
              </span>
              <span className="text-[11px] font-semibold text-[#c9beae]">
                {activeScenario.replace(/_/g, ' ')}
              </span>
            </div>
          )}
        </div>

        {/* RIGHT */}
        <div className="flex items-center gap-2.5 md:gap-4">

          {/* Live connection */}
          <div className="hidden xl:flex items-center gap-2 text-[11px] text-[#8a7d6c]">
            <Radio className="w-3.5 h-3.5" />
            <span>FastAPI :8000</span>
            <span className="w-1.5 h-1.5 rounded-full bg-[#65a30d]" />
          </div>

          {/* Timestamp */}
          {lastUpdated && (
            <div className="hidden md:flex items-center gap-2 text-[11px] text-[#8a7d6c]">
              <Clock className="w-3.5 h-3.5" />
              <span>Updated {new Date(lastUpdated).toLocaleTimeString()}</span>
            </div>
          )}

          {/* Refresh */}
          <div className="rounded-lg border border-white/[0.08]">
            <RefreshButton onRefresh={onRefresh} loading={refreshing} />
          </div>

          <label className="flex h-9 cursor-pointer items-center gap-2 rounded-lg border border-[#d97706]/30 bg-[#d97706]/10 px-3 text-[11px] font-semibold text-[#f0b063] hover:bg-[#d97706]/[0.16] transition-colors">
            <Upload className="h-3.5 w-3.5" />
            <span>{loading ? 'Analyzing…' : 'Upload Data'}</span>
            <input type="file" accept=".pcap,.pcapng,.cap,.csv" className="hidden" onChange={handlePcapChange} disabled={loading} />
          </label>

          {fileName && (
            <button type="button" onClick={clearPcap} title="Clear active PCAP" className="flex h-9 max-w-40 items-center gap-1.5 rounded-lg border border-[#65a30d]/25 bg-[#65a30d]/10 px-2.5 text-[10px] text-[#a3c95a]">
              <span className="truncate">{fileName}</span>
              <X className="h-3 w-3 shrink-0" />
            </button>
          )}

          {error && <span className="hidden max-w-44 truncate text-[10px] text-[#f08a8a] xl:inline" title={error}>{error}</span>}

          {/* Profile */}
          <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-[#3e3226] text-white shrink-0">
            <span className="text-[10px] font-bold tracking-wider">TC</span>
          </div>
        </div>
      </div>
    </header>
  );
}
