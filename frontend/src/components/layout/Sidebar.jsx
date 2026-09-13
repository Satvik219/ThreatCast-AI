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
  Cpu,
  Database,
  Radio,
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

export default function Sidebar({
  isOpen,
  onClose,
}) {
  return (
    <>
      {/* =====================================================
          MOBILE BACKDROP
      ===================================================== */}

      {isOpen && (
        <div
          className="
            fixed inset-0
            z-40
            bg-black/70
            backdrop-blur-sm
            lg:hidden
          "
          onClick={onClose}
        />
      )}

      {/* =====================================================
          SIDEBAR
      ===================================================== */}

      <aside
        className={`
          fixed
          top-0
          left-0
          bottom-0
          z-50
          w-64
          flex
          flex-col

          bg-[#050608]
          text-[#B8C0C8]

          border-r
          border-white/[0.08]

          shadow-[15px_0_50px_rgba(0,0,0,0.25)]

          transition-transform
          duration-300
          ease-out

          lg:translate-x-0

          ${
            isOpen
              ? "translate-x-0"
              : "-translate-x-full"
          }
        `}
      >

        {/* ===================================================
            BRAND
        =================================================== */}

        <div
          className="
            relative
            px-5
            py-5
            border-b
            border-white/[0.08]
            bg-gradient-to-b
            from-white/[0.025]
            to-transparent
          "
        >

          <div className="flex items-center justify-between">

            {/* BRAND */}
            <div className="flex items-center gap-3">

              {/* Chrome logo */}
              <div
                className="
                  relative
                  w-10
                  h-10
                  rounded-xl
                  p-[1px]

                  bg-gradient-to-br
                  from-[#E8EDF2]
                  via-[#59636D]
                  to-[#151A20]

                  shadow-[0_0_20px_rgba(184,192,200,0.08)]
                "
              >

                <div
                  className="
                    relative
                    w-full
                    h-full
                    rounded-[11px]

                    flex
                    items-center
                    justify-center

                    bg-[#080A0D]

                    overflow-hidden
                  "
                >

                  <div
                    className="
                      absolute
                      inset-0

                      bg-[radial-gradient(circle_at_50%_20%,rgba(0,229,255,0.16),transparent_55%)]
                    "
                  />

                  <Shield
                    className="
                      relative
                      w-5
                      h-5

                      text-[#E8EDF2]

                      drop-shadow-[0_0_7px_rgba(0,229,255,0.45)]
                    "
                  />

                </div>
              </div>

              {/* BRAND TEXT */}
              <div>

                <div className="flex items-center gap-2">

                  <span
                    className="
                      font-extrabold
                      tracking-[0.16em]
                      text-sm
                      font-mono
                      text-[#E8EDF2]
                    "
                  >
                    THREATCAST
                  </span>

                  <span
                    className="
                      text-[8px]
                      font-bold
                      tracking-wider

                      px-1.5
                      py-0.5

                      rounded

                      bg-[#00E5FF]/10
                      text-[#00E5FF]

                      border
                      border-[#00E5FF]/25

                      shadow-[0_0_10px_rgba(0,229,255,0.08)]
                    "
                  >
                    AI
                  </span>

                </div>

                <p
                  className="
                    mt-1
                    text-[9px]
                    tracking-[0.16em]
                    text-[#59636D]
                    uppercase
                    font-semibold
                  "
                >
                  Early Warning Engine
                </p>

              </div>

            </div>

            {/* MOBILE CLOSE */}
            <button
              onClick={onClose}
              className="
                lg:hidden
                p-1.5
                rounded-lg

                text-[#59636D]

                hover:text-[#E8EDF2]
                hover:bg-white/[0.05]

                transition-all
              "
              aria-label="Close navigation"
              type="button"
            >
              <X className="w-4 h-4" />
            </button>

          </div>

          {/* Decorative line */}
          <div
            className="
              mt-5
              h-px

              bg-gradient-to-r
              from-[#00E5FF]/30
              via-[#B8C0C8]/15
              to-transparent
            "
          />

        </div>

        {/* ===================================================
            NAVIGATION
        =================================================== */}

        <nav
          className="
            flex-1
            px-3
            py-5

            space-y-1

            overflow-y-auto
          "
        >

          <div
            className="
              px-3
              pb-3

              text-[9px]
              font-bold
              uppercase
              tracking-[0.2em]

              text-[#59636D]

              font-mono
            "
          >
            Platform Intelligence
          </div>

          {/* EXISTING NAVIGATION */}
          {NAV_ITEMS.map((item) => {

            const Icon =
              ICON_MAP[item.icon] ||
              LayoutDashboard;

            return (
              <NavLink
                key={item.id}
                to={item.path}
                onClick={() =>
                  onClose && onClose()
                }
                className={({ isActive }) =>
                  `
                    relative

                    flex
                    items-center
                    gap-3

                    px-3
                    py-2.5

                    rounded-xl

                    text-xs
                    font-semibold

                    group

                    transition-all
                    duration-200

                    ${
                      isActive
                        ? `
                          bg-[#11161B]
                          text-[#E8EDF2]

                          border
                          border-[#00E5FF]/15

                          shadow-[
                            inset_0_1px_0_rgba(255,255,255,0.035),
                            0_0_20px_rgba(0,229,255,0.04)
                          ]
                        `
                        : `
                          text-[#718096]

                          border
                          border-transparent

                          hover:text-[#B8C0C8]
                          hover:bg-white/[0.025]
                          hover:border-white/[0.06]
                        `
                    }
                  `
                }
              >
                {({ isActive }) => (
                  <>

                    {/* Active indicator */}
                    {isActive && (
                      <span
                        className="
                          absolute

                          left-0
                          top-2.5
                          bottom-2.5

                          w-[2px]

                          rounded-full

                          bg-[#00E5FF]

                          shadow-[0_0_10px_rgba(0,229,255,0.9)]
                        "
                      />
                    )}

                    {/* Icon */}
                    <Icon
                      className={`
                        w-4
                        h-4

                        transition-all

                        ${
                          isActive
                            ? `
                              text-[#00E5FF]

                              drop-shadow-[0_0_6px_rgba(0,229,255,0.5)]
                            `
                            : `
                              text-[#59636D]

                              group-hover:text-[#B8C0C8]
                            `
                        }
                      `}
                    />

                    {/* Label */}
                    <span className="flex-1">
                      {item.label}
                    </span>

                    {/* Existing badges */}
                    {item.id === "forecast" && (
                      <span
                        className="
                          text-[8px]
                          font-mono

                          px-1.5
                          py-0.5

                          rounded

                          bg-[#00E5FF]/10
                          text-[#00E5FF]

                          border
                          border-[#00E5FF]/20
                        "
                      >
                        LSTM
                      </span>
                    )}

                    {item.id === "disagreements" && (
                      <span
                        className="
                          text-[8px]
                          font-mono

                          px-1.5
                          py-0.5

                          rounded

                          bg-[#A855F7]/10
                          text-[#A855F7]

                          border
                          border-[#A855F7]/20
                        "
                      >
                        SIGNAL
                      </span>
                    )}

                  </>
                )}
              </NavLink>
            );
          })}

          {/* =================================================
              WORLD MODEL
              ================================================= */}

          <NavLink
            to="/world-model"
            onClick={() =>
              onClose && onClose()
            }
            className={({ isActive }) =>
              `
                relative

                flex
                items-center
                gap-3

                px-3
                py-2.5

                rounded-xl

                text-xs
                font-semibold

                group

                transition-all
                duration-200

                ${
                  isActive
                    ? `
                      bg-[#11161B]
                      text-[#E8EDF2]

                      border
                      border-[#00E5FF]/15

                      shadow-[0_0_20px_rgba(0,229,255,0.04)]
                    `
                    : `
                      text-[#718096]

                      border
                      border-transparent

                      hover:text-[#B8C0C8]
                      hover:bg-white/[0.025]
                      hover:border-white/[0.06]
                    `
                }
              `
            }
          >

            {({ isActive }) => (
              <>

                {/* Active cyan indicator */}
                {isActive && (
                  <span
                    className="
                      absolute

                      left-0
                      top-2.5
                      bottom-2.5

                      w-[2px]

                      rounded-full

                      bg-[#00E5FF]

                      shadow-[0_0_10px_rgba(0,229,255,0.9)]
                    "
                  />
                )}

                {/* World Model icon */}
                <Cpu
                  className={`
                    w-4
                    h-4

                    transition-all

                    ${
                      isActive
                        ? `
                          text-[#00E5FF]

                          drop-shadow-[0_0_6px_rgba(0,229,255,0.5)]
                        `
                        : `
                          text-[#59636D]

                          group-hover:text-[#B8C0C8]
                        `
                    }
                  `}
                />

                {/* Label */}
                <span className="flex-1">
                  World Model
                </span>

                {/* AI badge */}
                <span
                  className="
                    text-[8px]
                    font-mono

                    px-1.5
                    py-0.5

                    rounded

                    bg-[#00E5FF]/10
                    text-[#00E5FF]

                    border
                    border-[#00E5FF]/20
                  "
                >
                  AI
                </span>

              </>
            )}

          </NavLink>

        </nav>

        {/* ===================================================
            SYSTEM STATUS
        =================================================== */}

        <div
          className="
            p-4

            border-t
            border-white/[0.08]

            bg-gradient-to-t
            from-[#030405]
            to-transparent

            space-y-3
          "
        >

          {/* SYSTEM STATUS CARD */}
          <div
            className="
              relative

              p-3

              rounded-xl

              bg-[#0D1115]

              border
              border-white/[0.08]

              overflow-hidden
            "
          >

            {/* Cyan glow */}
            <div
              className="
                absolute

                -top-10
                -right-10

                w-24
                h-24

                rounded-full

                bg-[#00E5FF]/5

                blur-2xl
              "
            />

            {/* CTU13 */}
            <div
              className="
                relative

                flex
                items-center
                justify-between

                text-[10px]
              "
            >

              <span
                className="
                  flex
                  items-center
                  gap-2

                  text-[#718096]
                "
              >

                <span
                  className="
                    w-1.5
                    h-1.5

                    rounded-full

                    bg-[#00FF9C]

                    shadow-[0_0_7px_rgba(0,255,156,0.9)]
                  "
                />

                CTU13 LSTM

              </span>

              <span
                className="
                  font-mono
                  text-[#00FF9C]
                  font-bold
                "
              >
                ACTIVE
              </span>

            </div>

            {/* API */}
            <div
              className="
                mt-3

                flex
                items-center
                justify-between

                text-[10px]
              "
            >

              <span
                className="
                  flex
                  items-center
                  gap-2

                  text-[#718096]
                "
              >

                <span
                  className="
                    w-1.5
                    h-1.5

                    rounded-full

                    bg-[#00E5FF]

                    shadow-[0_0_7px_rgba(0,229,255,0.8)]
                  "
                />

                API CONTRACT

              </span>

              <span
                className="
                  font-mono
                  text-[#B8C0C8]
                "
              >
                FASTAPI:8000
              </span>

            </div>

            {/* INPUT WINDOW */}
            <div
              className="
                mt-3

                flex
                items-center
                justify-between

                text-[10px]
              "
            >

              <span
                className="
                  flex
                  items-center
                  gap-2

                  text-[#718096]
                "
              >

                <span
                  className="
                    w-1.5
                    h-1.5

                    rounded-full

                    bg-[#59636D]
                  "
                />

                INPUT WINDOW

              </span>

              <span
                className="
                  font-mono
                  text-[#B8C0C8]
                "
              >
                5 × 30s
              </span>

            </div>

          </div>

          {/* USER / CONSOLE */}
          <div
            className="
              flex
              items-center
              justify-between

              pt-1
              px-1
            "
          >

            <div
              className="
                flex
                items-center
                gap-2.5
              "
            >

              {/* User badge */}
              <div
                className="
                  w-8
                  h-8

                  rounded-lg

                  p-[1px]

                  bg-gradient-to-br
                  from-[#E8EDF2]
                  to-[#59636D]
                "
              >

                <div
                  className="
                    w-full
                    h-full

                    rounded-[7px]

                    flex
                    items-center
                    justify-center

                    bg-[#0D1115]

                    text-[#E8EDF2]

                    font-bold
                    text-[9px]

                    font-mono
                  "
                >
                  TC
                </div>

              </div>

              <div>

                <p
                  className="
                    text-[10px]
                    font-bold
                    text-[#B8C0C8]
                    leading-tight
                  "
                >
                  SecOps Lead
                </p>

                <p
                  className="
                    mt-0.5
                    text-[8px]
                    text-[#59636D]
                    font-mono
                  "
                >
                  SOC ANALYST CONSOLE
                </p>

              </div>

            </div>

            {/* Settings */}
            <button
              className="
                w-7
                h-7

                rounded-lg

                flex
                items-center
                justify-center

                text-[#59636D]

                hover:text-[#B8C0C8]
                hover:bg-white/[0.04]

                transition-all
              "
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