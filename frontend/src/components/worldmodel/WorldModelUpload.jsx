import React, { useMemo, useRef, useState } from "react";
import {
  UploadCloud,
  FileText,
  Play,
  X,
  CheckCircle2,
  AlertCircle,
  Activity,
  Shield,
  Network,
  Brain,
  Search,
  Database,
  Clock3,
  Radio,
} from "lucide-react";

const API_BASE_URL = "http://127.0.0.1:8000";

const ALLOWED_EXTENSIONS = [
  ".csv",
  ".pcap",
  ".pcapng",
  ".cap",
];

const FEATURE_NAMES = [
  "Flow_Count",
  "Total_Packets",
  "Total_Bytes",
  "Total_Source_Bytes",
  "Avg_Duration",
  "Avg_Packets_Per_Flow",
  "Avg_Bytes_Per_Flow",
  "Flow_Count_Change",
  "Total_Packets_Change",
  "Total_Bytes_Change",
  "Total_Source_Bytes_Change",
  "Avg_Duration_Change",
];

const PACKET_EVIDENCE_LABELS = {
  packet_count: "Packet Count",
  avg_packet_size: "Average Packet Size",
  packet_size_variance: "Packet Size Variance",
  ttl_mean: "TTL Mean",
  ttl_variance: "TTL Variance",
  tcp_window_mean: "TCP Window Mean",
  tcp_window_variance: "TCP Window Variance",
  syn_count: "TCP SYN",
  ack_count: "TCP ACK",
  rst_count: "TCP RST",
  fin_count: "TCP FIN",
  psh_count: "TCP PSH",
  fragmented_packet_count: "Fragmented Packets",
  unique_source_ips: "Unique Source IPs",
  unique_destination_ips: "Unique Destination IPs",
  unique_destination_ports: "Unique Destination Ports",
  max_unique_ports_per_source: "Max Ports / Source",
  port_scan_signature: "Port Scan Signature",
  scan_entropy: "Scan Entropy",
  window_duration: "Window Duration",
};

function formatNumber(value, digits = 2) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return String(value);
  }

  return number.toLocaleString(undefined, {
    maximumFractionDigits: digits,
  });
}

function formatPercent(value) {
  if (value === null || value === undefined) {
    return "—";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  return `${number.toFixed(2)}%`;
}

function formatBytes(value) {
  if (value === null || value === undefined) {
    return "—";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  if (Math.abs(number) >= 1024 * 1024 * 1024) {
    return `${(number / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  if (Math.abs(number) >= 1024 * 1024) {
    return `${(number / (1024 * 1024)).toFixed(2)} MB`;
  }

  if (Math.abs(number) >= 1024) {
    return `${(number / 1024).toFixed(2)} KB`;
  }

  return `${number.toFixed(0)} B`;
}

function getExtension(filename = "") {
  const lower = filename.toLowerCase();

  const match = lower.match(/\.[^.]+$/);

  return match ? match[0] : "";
}

function isAllowedFile(file) {
  return ALLOWED_EXTENSIONS.includes(
    getExtension(file?.name)
  );
}

function getSourceLabel(result) {
  if (result?.input_source === "pcap") {
    return "PCAP";
  }

  if (result?.input_source === "csv") {
    return "CSV";
  }

  return "UNKNOWN";
}

function Card({ title, icon: Icon, children, className = "" }) {
  return (
    <section
      className={`
        rounded-2xl
        border border-cyber-brown-200
        bg-white
        shadow-sm
        overflow-hidden
        ${className}
      `}
    >
      <div className="flex items-center gap-3 border-b border-cyber-brown-100 px-5 py-4">
        {Icon && (
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-50 text-cyan-600">
            <Icon className="h-4 w-4" />
          </div>
        )}

        <h2 className="text-sm font-bold uppercase tracking-[0.12em] text-cyber-brown-900">
          {title}
        </h2>
      </div>

      <div className="p-5">
        {children}
      </div>
    </section>
  );
}

function Stat({ label, value, sub }) {
  return (
    <div className="rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-4">
      <div className="text-[10px] font-bold uppercase tracking-[0.14em] text-cyber-brown-400">
        {label}
      </div>

      <div className="mt-2 text-xl font-bold text-cyber-brown-900">
        {value}
      </div>

      {sub && (
        <div className="mt-1 text-[11px] text-cyber-brown-500">
          {sub}
        </div>
      )}
    </div>
  );
}

function RiskCard({ item }) {
  const probability = Number(
    item?.risk_probability_percent ?? 0
  );

  const predicted = Boolean(
    item?.predicted_attack
  );

  return (
    <div
      className={`
        rounded-2xl
        border
        p-5
        ${
          predicted
            ? "border-red-200 bg-red-50/60"
            : "border-cyber-brown-100 bg-[#fbf8f4]"
        }
      `}
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-[0.18em] text-cyber-brown-400">
            Forecast
          </div>

          <div className="mt-1 text-lg font-bold text-cyber-brown-900">
            {item?.horizon || "T+?"}
          </div>
        </div>

        {predicted ? (
          <div className="rounded-full border border-red-200 bg-red-100 px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-red-700">
            Attack Signal
          </div>
        ) : (
          <div className="rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-emerald-700">
            Below Threshold
          </div>
        )}
      </div>

      <div className="mt-6">
        <div className="flex items-end justify-between">
          <span className="text-3xl font-bold text-cyber-brown-900">
            {formatPercent(probability)}
          </span>

          <span className="text-[10px] text-cyber-brown-400">
            threshold {formatPercent(
              Number(item?.threshold ?? 0) * 100
            )}
          </span>
        </div>

        <div className="mt-3 h-2 overflow-hidden rounded-full bg-cyber-brown-100">
          <div
            className={`
              h-full rounded-full transition-all
              ${
                predicted
                  ? "bg-red-500"
                  : "bg-cyan-500"
              }
            `}
            style={{
              width: `${Math.min(
                100,
                Math.max(0, probability)
              )}%`,
            }}
          />
        </div>
      </div>
    </div>
  );
}

export default function WorldModelUpload() {
  const inputRef = useRef(null);

  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [scenario, setScenario] = useState("");

  const fileExtension = useMemo(
    () => getExtension(file?.name),
    [file]
  );

  const isPCAP =
    fileExtension === ".pcap" ||
    fileExtension === ".pcapng" ||
    fileExtension === ".cap";

  const chooseFile = () => {
    setError("");

    if (inputRef.current) {
      inputRef.current.click();
    }
  };

  const handleFileChange = (event) => {
    const selectedFile =
      event.target.files?.[0] || null;

    setError("");
    setResult(null);

    if (!selectedFile) {
      setFile(null);
      return;
    }

    if (!isAllowedFile(selectedFile)) {
      setFile(null);

      setError(
        "Unsupported file type. Please select a CSV, PCAP, PCAPNG, or CAP file."
      );

      event.target.value = "";
      return;
    }

    setFile(selectedFile);
  };

  const clearAll = () => {
    setFile(null);
    setResult(null);
    setError("");
    setScenario("");

    if (inputRef.current) {
      inputRef.current.value = "";
    }
  };

  const runWorldModel = async () => {
    if (!file) {
      setError(
        "Please choose a CSV or PCAP file first."
      );
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const formData = new FormData();

      formData.append("file", file);

      let endpoint =
        `${API_BASE_URL}/api/world-model/risk`;

      /*
       * Scenario is valid for CTU13 CSV input.
       * PCAP input is intentionally scenario-independent.
       */
      if (!isPCAP && scenario) {
        endpoint += `?scenario=${encodeURIComponent(
          scenario
        )}`;
      }

      const response = await fetch(endpoint, {
        method: "POST",
        body: formData,
      });

      let data = null;

      try {
        data = await response.json();
      } catch {
        throw new Error(
          `Backend returned an invalid response (HTTP ${response.status}).`
        );
      }

      if (!response.ok) {
        const detail =
          data?.detail ||
          data?.message ||
          `World model request failed with HTTP ${response.status}.`;

        throw new Error(detail);
      }

      if (!data?.success) {
        throw new Error(
          data?.detail ||
            "World model did not return a successful result."
        );
      }

      setResult(data);
    } catch (err) {
      console.error(
        "World Model upload failed:",
        err
      );

      setError(
        err?.message ||
          "Unable to connect to the World Model backend."
      );
    } finally {
      setLoading(false);
    }
  };

  const sourceLabel = getSourceLabel(result);

  const rollout =
    result?.world_model?.rollout || [];

  const packetEvidence =
    result?.packet_evidence || null;

  const pcapMetadata =
    result?.pcap_metadata || null;

  const stagePrediction =
    result?.trained_stage_prediction || null;

  const featureEvidence =
    result?.explainability?.feature_evidence ||
    stagePrediction?.evidence ||
    null;

  const inputPayload =
    result?.input || null;

  return (
    <div className="space-y-6">

      {/* =========================================================
          UPLOAD PANEL
      ========================================================= */}

      <Card
        title="Network Telemetry Input"
        icon={UploadCloud}
      >
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_auto]">

          <div>
            <div
              className="
                rounded-2xl
                border-2 border-dashed
                border-cyber-brown-200
                bg-[#fbf8f4]
                p-8
                text-center
                transition-all
                hover:border-cyan-300
                hover:bg-cyan-50/30
              "
            >
              <input
                ref={inputRef}
                type="file"
                className="hidden"
                accept=".csv,.pcap,.pcapng,.cap"
                onChange={handleFileChange}
              />

              {!file ? (
                <>
                  <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-50 text-cyan-600">
                    <UploadCloud className="h-7 w-7" />
                  </div>

                  <h3 className="mt-4 text-base font-bold text-cyber-brown-900">
                    Upload network telemetry
                  </h3>

                  <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-cyber-brown-500">
                    Upload a CTU13-compatible CSV or a
                    raw PCAP/PCAPNG/CAP capture. PCAP
                    traffic is converted into 30-second
                    temporal states before world-model
                    inference.
                  </p>

                  <button
                    type="button"
                    onClick={chooseFile}
                    className="
                      mt-6
                      inline-flex
                      items-center
                      gap-2
                      rounded-xl
                      bg-[#050608]
                      px-5
                      py-3
                      text-xs
                      font-bold
                      uppercase
                      tracking-wider
                      text-white
                      shadow-lg
                      transition-all
                      hover:bg-[#11161B]
                    "
                  >
                    <UploadCloud className="h-4 w-4" />
                    Choose File
                  </button>

                  <div className="mt-4 flex flex-wrap justify-center gap-2">
                    {[
                      "CSV",
                      "PCAP",
                      "PCAPNG",
                      "CAP",
                    ].map((type) => (
                      <span
                        key={type}
                        className="
                          rounded-full
                          border border-cyber-brown-200
                          bg-white
                          px-3 py-1
                          text-[9px]
                          font-bold
                          tracking-wider
                          text-cyber-brown-500
                        "
                      >
                        {type}
                      </span>
                    ))}
                  </div>
                </>
              ) : (
                <>
                  <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-600">
                    <FileText className="h-7 w-7" />
                  </div>

                  <h3 className="mt-4 break-all text-base font-bold text-cyber-brown-900">
                    {file.name}
                  </h3>

                  <p className="mt-2 text-xs text-cyber-brown-500">
                    {(file.size / 1024 / 1024).toFixed(
                      2
                    )}{" "}
                    MB
                    {" • "}
                    {fileExtension.toUpperCase()}
                  </p>

                  <div className="mt-5 flex flex-wrap justify-center gap-3">
                    <button
                      type="button"
                      onClick={chooseFile}
                      className="
                        inline-flex
                        items-center
                        gap-2
                        rounded-xl
                        border
                        border-cyber-brown-200
                        bg-white
                        px-4
                        py-2.5
                        text-xs
                        font-bold
                        text-cyber-brown-700
                        transition-all
                        hover:border-cyan-300
                        hover:text-cyan-700
                      "
                    >
                      <UploadCloud className="h-4 w-4" />
                      Change File
                    </button>

                    <button
                      type="button"
                      onClick={clearAll}
                      className="
                        inline-flex
                        items-center
                        gap-2
                        rounded-xl
                        border
                        border-red-200
                        bg-red-50
                        px-4
                        py-2.5
                        text-xs
                        font-bold
                        text-red-700
                        transition-all
                        hover:bg-red-100
                      "
                    >
                      <X className="h-4 w-4" />
                      Clear
                    </button>
                  </div>
                </>
              )}
            </div>

            {/* Scenario control */}
            {!isPCAP && (
              <div className="mt-4 rounded-xl border border-cyber-brown-100 bg-white p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <div className="text-xs font-bold text-cyber-brown-900">
                      CTU13 Scenario
                    </div>

                    <div className="mt-1 text-[11px] text-cyber-brown-500">
                      Leave as Auto to use the scenario
                      detected from the uploaded CSV.
                    </div>
                  </div>

                  <select
                    value={scenario}
                    onChange={(event) =>
                      setScenario(event.target.value)
                    }
                    className="
                      rounded-xl
                      border border-cyber-brown-200
                      bg-[#fbf8f4]
                      px-4 py-2.5
                      text-xs
                      font-semibold
                      text-cyber-brown-800
                      outline-none
                      focus:border-cyan-400
                    "
                  >
                    <option value="">
                      Auto Detect
                    </option>

                    {Array.from(
                      { length: 13 },
                      (_, index) => index + 1
                    ).map((value) => (
                      <option
                        key={value}
                        value={value}
                      >
                        Scenario {value}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            )}

            {isPCAP && (
              <div className="mt-4 rounded-xl border border-cyan-200 bg-cyan-50/50 p-4">
                <div className="flex items-start gap-3">
                  <Radio className="mt-0.5 h-4 w-4 shrink-0 text-cyan-600" />

                  <div>
                    <div className="text-xs font-bold text-cyan-900">
                      Raw packet capture detected
                    </div>

                    <div className="mt-1 text-[11px] leading-5 text-cyan-800">
                      The backend will parse packets,
                      aggregate them into 30-second
                      temporal states, construct the
                      12 model features, and then run
                      the CTU13 temporal world model.
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* ACTION */}
          <div className="flex flex-col justify-end gap-3 lg:min-w-[210px]">

            <button
              type="button"
              onClick={runWorldModel}
              disabled={!file || loading}
              className="
                inline-flex
                min-h-[52px]
                items-center
                justify-center
                gap-2
                rounded-xl
                bg-[#050608]
                px-6
                py-3
                text-xs
                font-bold
                uppercase
                tracking-[0.12em]
                text-white
                shadow-lg
                transition-all
                hover:bg-[#11161B]
                disabled:cursor-not-allowed
                disabled:opacity-40
              "
            >
              {loading ? (
                <>
                  <span
                    className="
                      h-4 w-4
                      animate-spin
                      rounded-full
                      border-2
                      border-white/30
                      border-t-white
                    "
                  />
                  Running...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  Run World Model
                </>
              )}
            </button>

            <div className="rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-4">
              <div className="text-[9px] font-bold uppercase tracking-[0.16em] text-cyber-brown-400">
                Pipeline
              </div>

              <div className="mt-2 space-y-2 text-[10px] text-cyber-brown-600">
                <div className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-500" />
                  Upload
                </div>

                <div className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-500" />
                  Temporal aggregation
                </div>

                <div className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-500" />
                  64-D latent encoding
                </div>

                <div className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-500" />
                  T+1 / T+2 / T+3
                </div>

                <div className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-500" />
                  Stage + evidence
                </div>
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* =========================================================
          ERROR
      ========================================================= */}

      {error && (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-5">
          <div className="flex items-start gap-3">
            <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-600" />

            <div>
              <div className="text-sm font-bold text-red-900">
                World Model Request Failed
              </div>

              <div className="mt-1 text-xs leading-5 text-red-700">
                {error}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================
          RESULTS
      ========================================================= */}

      {result && (
        <div className="space-y-6">

          {/* SUCCESS BANNER */}
          <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-5">
            <div className="flex items-start gap-3">
              <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" />

              <div>
                <div className="text-sm font-bold text-emerald-900">
                  World Model Inference Complete
                </div>

                <div className="mt-1 text-xs leading-5 text-emerald-800">
                  {result.pipeline ||
                    "World Model inference completed successfully."}
                </div>
              </div>
            </div>
          </div>

          {/* INPUT SUMMARY */}
          <Card
            title="Input Summary"
            icon={Database}
          >
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">

              <Stat
                label="Source"
                value={sourceLabel}
                sub={result.filename}
              />

              <Stat
                label="Temporal States"
                value={formatNumber(
                  result.states,
                  0
                )}
                sub={`${result.sequence_length || 5} states / input`}
              />

              <Stat
                label="Features"
                value={formatNumber(
                  result.feature_count,
                  0
                )}
                sub="Model input features"
              />

              <Stat
                label="Scenario"
                value={
                  result.scenario
                    ? `Scenario ${result.scenario}`
                    : "Not specified"
                }
                sub={
                  isPCAP
                    ? "PCAP is scenario-independent"
                    : "Detected / supplied"
                }
              />
            </div>

            <div className="mt-4 rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-4">
              <div className="text-[10px] font-bold uppercase tracking-[0.15em] text-cyber-brown-400">
                Input Features
              </div>

              <div className="mt-3 flex flex-wrap gap-2">
                {(
                  result.features ||
                  FEATURE_NAMES
                ).map((feature) => (
                  <span
                    key={feature}
                    className="
                      rounded-full
                      border border-cyber-brown-200
                      bg-white
                      px-2.5 py-1
                      font-mono
                      text-[9px]
                      text-cyber-brown-600
                    "
                  >
                    {feature}
                  </span>
                ))}
              </div>
            </div>
          </Card>

          {/* PCAP METADATA */}
          {pcapMetadata && (
            <Card
              title="PCAP Metadata"
              icon={Radio}
            >
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">

                <Stat
                  label="Packets Read"
                  value={formatNumber(
                    pcapMetadata.packet_count,
                    0
                  )}
                />

                <Stat
                  label="Ignored"
                  value={formatNumber(
                    pcapMetadata.ignored_packet_count,
                    0
                  )}
                  sub="Non-usable packets"
                />

                <Stat
                  label="Temporal States"
                  value={formatNumber(
                    pcapMetadata.state_count,
                    0
                  )}
                />

                <Stat
                  label="Window"
                  value={`${formatNumber(
                    pcapMetadata.window_seconds,
                    0
                  )} sec`}
                />

                <Stat
                  label="Non-empty States"
                  value={formatNumber(
                    pcapMetadata.non_empty_state_count,
                    0
                  )}
                />

                <Stat
                  label="Empty States"
                  value={formatNumber(
                    pcapMetadata.empty_state_count,
                    0
                  )}
                />

                <Stat
                  label="First Packet"
                  value={
                    pcapMetadata.first_packet_timestamp
                      ? new Date(
                          pcapMetadata.first_packet_timestamp
                        ).toLocaleTimeString()
                      : "—"
                  }
                />

                <Stat
                  label="Last Packet"
                  value={
                    pcapMetadata.last_packet_timestamp
                      ? new Date(
                          pcapMetadata.last_packet_timestamp
                        ).toLocaleTimeString()
                      : "—"
                  }
                />
              </div>
            </Card>
          )}

          {/* RISK FORECAST */}
          <Card
            title="Multi-Step Risk Forecast"
            icon={Activity}
          >
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {rollout.length > 0 ? (
                rollout.map((item) => (
                  <RiskCard
                    key={
                      item.step ??
                      item.horizon
                    }
                    item={item}
                  />
                ))
              ) : (
                <div className="col-span-full rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-5 text-sm text-cyber-brown-500">
                  No rollout predictions were returned.
                </div>
              )}
            </div>

            {result.world_model?.calibration && (
              <div className="mt-4 rounded-xl border border-cyan-200 bg-cyan-50/40 p-4">
                <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
                  <div>
                    <div className="text-[9px] font-bold uppercase tracking-[0.15em] text-cyan-700">
                      Calibration
                    </div>

                    <div className="mt-1 text-xs font-bold text-cyan-950">
                      {result.world_model.calibration
                        .method ||
                        "Scenario-adaptive calibration"}
                    </div>
                  </div>

                  <div className="text-[10px] text-cyan-800">
                    Scenario adaptive:{" "}
                    <strong>
                      {result.world_model.calibration
                        .scenario_adaptive
                        ? "Yes"
                        : "No"}
                    </strong>
                  </div>

                  <div className="text-[10px] text-cyan-800">
                    Calibration windows:{" "}
                    <strong>
                      {formatNumber(
                        result.world_model.calibration
                          .calibration_windows,
                        0
                      )}
                    </strong>
                  </div>
                </div>
              </div>
            )}
          </Card>

          {/* MODEL DETAILS */}
          <Card
            title="World Model Details"
            icon={Brain}
          >
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">

              <Stat
                label="Latent Dimension"
                value={
                  result.world_model
                    ?.latent_dimension ?? "—"
                }
                sub="Current latent representation"
              />

              <Stat
                label="History"
                value={
                  result.world_model
                    ?.sequence_length
                    ? `${result.world_model.sequence_length} states`
                    : "5 states"
                }
                sub="Temporal context"
              />

              <Stat
                label="Forecast Horizon"
                value={
                  result.world_model
                    ?.forecast_horizon
                    ? `${result.world_model.forecast_horizon} states`
                    : "3 states"
                }
                sub="Autoregressive rollout"
              />

              <Stat
                label="Rollout Shape"
                value={
                  result.world_model
                    ?.latent_rollout_shape
                    ? `[${result.world_model.latent_rollout_shape.join(
                        " × "
                      )}]`
                    : "—"
                }
                sub="Latent forecast tensor"
              />
            </div>

            {result.world_model?.checkpoint && (
              <div className="mt-4 rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-4">
                <div className="text-[9px] font-bold uppercase tracking-[0.15em] text-cyber-brown-400">
                  Checkpoint
                </div>

                <div className="mt-1 break-all font-mono text-[10px] text-cyber-brown-700">
                  {result.world_model.checkpoint}
                </div>
              </div>
            )}
          </Card>

          {/* STAGE PREDICTION */}
          {stagePrediction && (
            <Card
              title="Trained Stage Prediction"
              icon={Shield}
            >
              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">

                {Object.entries(
                  stagePrediction.probabilities ||
                    {}
                ).map(
                  ([
                    stageName,
                    stageData,
                  ]) => (
                    <div
                      key={stageName}
                      className="
                        rounded-2xl
                        border border-cyber-brown-100
                        bg-[#fbf8f4]
                        p-5
                      "
                    >
                      <div className="text-[10px] font-bold uppercase tracking-[0.13em] text-cyber-brown-400">
                        Stage
                      </div>

                      <div className="mt-1 text-sm font-bold text-cyber-brown-900">
                        {stageName}
                      </div>

                      <div className="mt-5 flex items-end justify-between">
                        <span className="text-2xl font-bold text-cyber-brown-900">
                          {formatPercent(
                            Number(
                              stageData?.probability_percent ??
                                Number(
                                  stageData?.probability ??
                                    0
                                ) * 100
                            )
                          )}
                        </span>

                        <span
                          className={`
                            rounded-full
                            px-2.5 py-1
                            text-[9px]
                            font-bold
                            uppercase
                            tracking-wider
                            ${
                              stageData?.predicted
                                ? "bg-cyan-100 text-cyan-700"
                                : "bg-cyber-brown-100 text-cyber-brown-500"
                            }
                          `}
                        >
                          {stageData?.predicted
                            ? "Predicted"
                            : "Not Predicted"}
                        </span>
                      </div>

                      <div className="mt-3 text-[10px] text-cyber-brown-500">
                        Threshold:{" "}
                        {formatPercent(
                          Number(
                            stageData?.threshold ??
                              0
                          ) * 100
                        )}
                      </div>
                    </div>
                  )
                )}
              </div>

              {stagePrediction.primary_stage && (
                <div className="mt-4 rounded-xl border border-cyan-200 bg-cyan-50/50 p-4">
                  <div className="text-[9px] font-bold uppercase tracking-[0.16em] text-cyan-700">
                    Primary Stage
                  </div>

                  <div className="mt-1 text-base font-bold text-cyan-950">
                    {
                      stagePrediction.primary_stage
                        .name
                    }
                  </div>

                  <div className="mt-1 text-xs text-cyan-800">
                    Probability:{" "}
                    {formatPercent(
                      Number(
                        stagePrediction.primary_stage
                          .probability_percent ??
                          Number(
                            stagePrediction.primary_stage
                              .probability ?? 0
                          ) * 100
                      )
                    )}
                  </div>
                </div>
              )}
            </Card>
          )}

          {/* MITRE MAPPING */}
          {stagePrediction?.mitre_mapping &&
            stagePrediction.mitre_mapping.length >
              0 && (
              <Card
                title="MITRE Interpretation"
                icon={Search}
              >
                <div className="space-y-3">
                  {stagePrediction.mitre_mapping.map(
                    (mapping, index) => (
                      <div
                        key={`${mapping.technique || "mapping"}-${index}`}
                        className="
                          rounded-xl
                          border border-cyber-brown-100
                          bg-[#fbf8f4]
                          p-4
                        "
                      >
                        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                          <div>
                            <div className="text-xs font-bold text-cyber-brown-900">
                              {mapping.stage ||
                                mapping.tactic ||
                                "Stage"}
                            </div>

                            <div className="mt-1 text-[11px] text-cyber-brown-600">
                              {mapping.technique ||
                                mapping.description ||
                                "MITRE interpretation"}
                            </div>
                          </div>

                          {mapping.technique_id && (
                            <span className="rounded-full border border-cyber-brown-200 bg-white px-3 py-1 font-mono text-[9px] font-bold text-cyber-brown-600">
                              {mapping.technique_id}
                            </span>
                          )}
                        </div>
                      </div>
                    )
                  )}
                </div>
              </Card>
            )}

          {/* PACKET EVIDENCE */}
          {packetEvidence && (
            <Card
              title="Packet-Level Evidence"
              icon={Network}
            >
              <div className="mb-4 rounded-xl border border-amber-200 bg-amber-50 p-4">
                <div className="text-xs font-bold text-amber-900">
                  Evidence, not additional model inputs
                </div>

                <div className="mt-1 text-[11px] leading-5 text-amber-800">
                  These packet-level telemetry values
                  come from the uploaded capture. They
                  provide operational evidence alongside
                  the trained model prediction; they are
                  not being presented as packet-level SHAP
                  attribution.
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                {Object.entries(packetEvidence)
                  .filter(
                    ([key]) =>
                      key !== "available" &&
                      key !== "source"
                  )
                  .map(
                    ([key, value]) => (
                      <Stat
                        key={key}
                        label={
                          PACKET_EVIDENCE_LABELS[
                            key
                          ] ||
                          key
                            .replaceAll("_", " ")
                            .replace(
                              /\b\w/g,
                              (letter) =>
                                letter.toUpperCase()
                            )
                        }
                        value={
                          key.includes("packet_size") ||
                          key === "avg_packet_size"
                            ? formatBytes(value)
                            : formatNumber(
                                value,
                                2
                              )
                        }
                      />
                    )
                  )}
              </div>
            </Card>
          )}

          {/* FEATURE EVIDENCE */}
          {featureEvidence && (
            <Card
              title="Feature-Level Evidence"
              icon={Activity}
            >
              <div className="grid grid-cols-1 gap-5 md:grid-cols-2">

                {featureEvidence
                  .top_distribution_shift_features && (
                  <div>
                    <div className="text-xs font-bold text-cyber-brown-900">
                      Distribution Shift
                    </div>

                    <div className="mt-3 space-y-2">
                      {featureEvidence.top_distribution_shift_features
                        .slice(0, 6)
                        .map(
                          (item, index) => (
                            <div
                              key={`${item.feature}-${index}`}
                              className="rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-3"
                            >
                              <div className="flex items-center justify-between gap-3">
                                <span className="font-mono text-[10px] font-semibold text-cyber-brown-800">
                                  {item.feature}
                                </span>

                                <span className="text-[10px] font-bold text-cyan-700">
                                  z ={" "}
                                  {formatNumber(
                                    item.standardized_value,
                                    3
                                  )}
                                </span>
                              </div>
                            </div>
                          )
                        )}
                    </div>
                  </div>
                )}

                {featureEvidence
                  .top_recent_change_features && (
                  <div>
                    <div className="text-xs font-bold text-cyber-brown-900">
                      Recent Change
                    </div>

                    <div className="mt-3 space-y-2">
                      {featureEvidence.top_recent_change_features
                        .slice(0, 6)
                        .map(
                          (item, index) => (
                            <div
                              key={`${item.feature}-${index}`}
                              className="rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-3"
                            >
                              <div className="flex items-center justify-between gap-3">
                                <span className="font-mono text-[10px] font-semibold text-cyber-brown-800">
                                  {item.feature}
                                </span>

                                <span className="text-[10px] font-bold text-cyan-700">
                                  Δ{" "}
                                  {formatNumber(
                                    item.delta,
                                    2
                                  )}
                                </span>
                              </div>
                            </div>
                          )
                        )}
                    </div>
                  </div>
                )}
              </div>

              <div className="mt-4 text-[10px] leading-5 text-cyber-brown-500">
                Method:{" "}
                {featureEvidence.method ||
                  "Feature-level telemetry evidence"}
                .
                {" "}
                This is not presented as causal
                attribution or packet-level SHAP.
              </div>
            </Card>
          )}

          {/* TEMPORAL INPUT */}
          {inputPayload?.sequence && (
            <Card
              title="Temporal Input"
              icon={Clock3}
            >
              <div className="overflow-x-auto rounded-xl border border-cyber-brown-100">
                <table className="min-w-full text-left">
                  <thead className="bg-[#fbf8f4]">
                    <tr>
                      <th className="px-4 py-3 text-[9px] font-bold uppercase tracking-wider text-cyber-brown-400">
                        Time
                      </th>

                      {(
                        inputPayload.feature_names ||
                        FEATURE_NAMES
                      ).map(
                        (feature) => (
                          <th
                            key={feature}
                            className="whitespace-nowrap px-4 py-3 text-[9px] font-bold uppercase tracking-wider text-cyber-brown-400"
                          >
                            {feature}
                          </th>
                        )
                      )}
                    </tr>
                  </thead>

                  <tbody>
                    {inputPayload.sequence.map(
                      (row, rowIndex) => (
                        <tr
                          key={rowIndex}
                          className="border-t border-cyber-brown-100"
                        >
                          <td className="whitespace-nowrap px-4 py-3 font-mono text-[9px] text-cyber-brown-600">
                            {inputPayload.timestamps?.[
                              rowIndex
                            ] || `State ${rowIndex + 1}`}
                          </td>

                          {row.map(
                            (value, columnIndex) => (
                              <td
                                key={columnIndex}
                                className="whitespace-nowrap px-4 py-3 font-mono text-[9px] text-cyber-brown-700"
                              >
                                {formatNumber(
                                  value,
                                  2
                                )}
                              </td>
                            )
                          )}
                        </tr>
                      )
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {/* CLASSIFIER SCOPE */}
          {result.classifier_scope && (
            <Card
              title="Model Scope"
              icon={Shield}
            >
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">

                <div className="rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-4">
                  <div className="text-[9px] font-bold uppercase tracking-[0.15em] text-cyber-brown-400">
                    Stage Supervision
                  </div>

                  <div className="mt-1 text-xs font-bold text-cyber-brown-900">
                    {result.classifier_scope
                      .supervision ||
                      "Not specified"}
                  </div>
                </div>

                <div className="rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-4">
                  <div className="text-[9px] font-bold uppercase tracking-[0.15em] text-cyber-brown-400">
                    Timestamped MITRE Labels
                  </div>

                  <div className="mt-1 text-xs font-bold text-cyber-brown-900">
                    {result.classifier_scope
                      .ground_truth_timestamped_mitre_labels
                      ? "Available"
                      : "Not available"}
                  </div>
                </div>

                <div className="rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-4">
                  <div className="text-[9px] font-bold uppercase tracking-[0.15em] text-cyber-brown-400">
                    Scenario 13 Training
                  </div>

                  <div className="mt-1 text-xs font-bold text-emerald-700">
                    {result.classifier_scope
                      .scenario_13_used_for_training
                      ? "Used"
                      : "Not used"}
                  </div>
                </div>

                <div className="rounded-xl border border-cyber-brown-100 bg-[#fbf8f4] p-4">
                  <div className="text-[9px] font-bold uppercase tracking-[0.15em] text-cyber-brown-400">
                    Scenario 13 Threshold Selection
                  </div>

                  <div className="mt-1 text-xs font-bold text-emerald-700">
                    {result.classifier_scope
                      .scenario_13_used_for_threshold_selection
                      ? "Used"
                      : "Not used"}
                  </div>
                </div>

              </div>
            </Card>
          )}

          {/* RAW PORT NOTE */}
          {result.explainability && (
            <div className="rounded-2xl border border-cyber-brown-200 bg-white p-5 shadow-sm">
              <div className="flex items-start gap-3">
                <Network className="mt-0.5 h-5 w-5 text-cyan-600" />

                <div>
                  <div className="text-sm font-bold text-cyber-brown-900">
                    Packet Attribution Scope
                  </div>

                  <div className="mt-1 text-xs leading-5 text-cyber-brown-600">
                    {result.explainability.note ||
                      "Packet-level telemetry is available as evidence where supplied by PCAP input."}
                  </div>

                  <div className="mt-3 flex flex-wrap gap-2">
                    <span className="rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[9px] font-bold text-emerald-700">
                      Packet Evidence:{" "}
                      {result.explainability
                        .packet_evidence_available
                        ? "AVAILABLE"
                        : "NOT AVAILABLE"}
                    </span>

                    <span className="rounded-full border border-cyber-brown-200 bg-[#fbf8f4] px-3 py-1 text-[9px] font-bold text-cyber-brown-600">
                      Raw Port Attribution:{" "}
                      {result.explainability
                        .raw_port_information_available
                        ? "AVAILABLE"
                        : "NOT AVAILABLE"}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}