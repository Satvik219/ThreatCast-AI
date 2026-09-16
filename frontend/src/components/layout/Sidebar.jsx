import React from "react";
import { NavLink } from "react-router-dom";

import {
  LayoutDashboard,
  Activity,
  TrendingUp,
  Network,
  GitCompare,
  ShieldAlert,
  Sparkles,
  Shield,
  Settings,
  X,
} from "lucide-react";

import { NAV_ITEMS } from "../../utils/constants";

const ICON_MAP = {
  LayoutDashboard,
  Activity,
  TrendingUp,
  Network,
  GitCompare,
  ShieldAlert,
  Sparkles,
};

// Small, muted labels for nav items that need a secondary tag.
// Kept deliberately quiet (no neon/glow) so they read as metadata,
// not as decoration competing with the primary label.
const NAV_TAGS = {
  forecast: "LSTM",
  disagreements: "Signal",
};

export default function Sidebar({ isOpen, onClose }) {
  return (
    <>
      {/* MOBILE BACKDROP */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={onClose}
        />
      )}

      {/* SIDEBAR */}
      <aside
        className={`
          fixed top-0 left-0 bottom-0 z-50 w-64
          flex flex-col
          bg-[#171310] text-[#c9beae]
          border-r border-white/[0.06]
          transition-transform duration-200 ease-out
          lg:translate-x-0
          ${isOpen ? "translate-x-0" : "-translate-x-full"}
        `}
      >
        {/* BRAND */}
        <div className="px-5 py-5 border-b border-white/[0.06]">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-[#b45309] flex items-center justify-center shrink-0">
                <Shield className="w-4.5 h-4.5 text-white" />
              </div>

              <div>
                <span className="font-bold tracking-wide text-sm text-white">
                  ThreatCast AI
                </span>
                <p className="mt-0.5 text-[10px] tracking-wide text-[#8a7d6c] uppercase font-medium">
                  Early Warning Engine
                </p>
              </div>
            </div>

            {/* MOBILE CLOSE */}
            <button
              onClick={onClose}
              className="lg:hidden p-1.5 rounded-lg text-[#8a7d6c] hover:text-white hover:bg-white/[0.06] transition-colors"
              aria-label="Close navigation"
              type="button"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* NAVIGATION */}
        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
          <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-wider text-[#6b5f50]">
            Navigation
          </div>

          {NAV_ITEMS.map((item) => {
            const Icon = ICON_MAP[item.icon] || LayoutDashboard;
            const tag = NAV_TAGS[item.id];

            return (
              <NavLink
                key={item.id}
                to={item.path}
                onClick={() => onClose && onClose()}
                className={({ isActive }) =>
                  `relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 ${
                    isActive
                      ? "bg-white/[0.08] text-white"
                      : "text-[#a99d8c] hover:text-white hover:bg-white/[0.04]"
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    {isActive && (
                      <span className="absolute left-0 top-2 bottom-2 w-[3px] rounded-full bg-[#d97706]" />
                    )}

                    <Icon
                      className={`w-4 h-4 shrink-0 ${
                        isActive ? "text-[#d97706]" : "text-[#8a7d6c]"
                      }`}
                    />

                    <span className="flex-1 truncate">{item.label}</span>

                    {tag && (
                      <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded bg-white/[0.06] text-[#a99d8c]">
                        {tag}
                      </span>
                    )}
                  </>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* SYSTEM STATUS */}
        <div className="p-4 border-t border-white/[0.06] space-y-3">
          <div className="rounded-lg bg-white/[0.04] p-3 space-y-2.5">
            <div className="flex items-center justify-between text-[11px]">
              <span className="flex items-center gap-2 text-[#8a7d6c]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#65a30d]" />
                CTU13 LSTM
              </span>
              <span className="font-medium text-[#65a30d]">Active</span>
            </div>

            <div className="flex items-center justify-between text-[11px]">
              <span className="flex items-center gap-2 text-[#8a7d6c]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#d97706]" />
                API
              </span>
              <span className="text-[#c9beae]">FastAPI :8000</span>
            </div>

            <div className="flex items-center justify-between text-[11px]">
              <span className="flex items-center gap-2 text-[#8a7d6c]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#6b5f50]" />
                Input window
              </span>
              <span className="text-[#c9beae]">5 × 30s</span>
            </div>
          </div>

          {/* USER */}
          <div className="flex items-center justify-between px-1">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-[#3e3226] flex items-center justify-center text-white text-[10px] font-bold shrink-0">
                TC
              </div>

              <div>
                <p className="text-[11px] font-semibold text-white leading-tight">
                  Security Analyst
                </p>
                <p className="mt-0.5 text-[10px] text-[#6b5f50]">
                  SOC Console
                </p>
              </div>
            </div>

            <button
              className="w-7 h-7 rounded-lg flex items-center justify-center text-[#8a7d6c] hover:text-white hover:bg-white/[0.06] transition-colors"
              aria-label="Settings"
              type="button"
            >
              <Settings className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
