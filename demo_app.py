"""Standalone, offline Streamlit interface for the ThreatCast models."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
from sklearn.decomposition import PCA

from backend.data.flagged_flows import get_flagged_flows
from backend.data.live_explainability import explain_sequence
from backend.ml.inference import FEATURE_NAMES, SEQUENCE_LENGTH, predict_early_warning
from backend.ml.input_pipeline import prepare_uploaded_csv
from backend.ml.pcap_adapter import prepare_uploaded_pcap
from backend.ml.pcap_attribution import analyze_pcap_attribution
from world_model.attack_stage import get_primary_stage, get_scenario_stages
from world_model.ctu13_risk_inference import predict_world_model_batch
from world_model.stage_inference import predict_stage_with_evidence


def _sequences(frame: pd.DataFrame) -> list[list[list[float]]]:
    if len(frame) < SEQUENCE_LENGTH:
        raise ValueError(
            f"At least {SEQUENCE_LENGTH} temporal states are required; received {len(frame)}."
        )
    values = frame[FEATURE_NAMES].astype(float).to_numpy()
    return [
        values[end - SEQUENCE_LENGTH : end].tolist()
        for end in range(SEQUENCE_LENGTH, len(values) + 1)
    ]


def _scenario_from(frame: pd.DataFrame, selected: int | None) -> int | None:
    if selected is not None:
        return selected
    if "Scenario" in frame.columns and not frame.empty:
        try:
            value = int(frame["Scenario"].iloc[-1])
            return value if 1 <= value <= 13 else None
        except (TypeError, ValueError):
            pass
    return None


def _flow_rows(items: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for item in items:
        rows.append(
            {
                "Source": item.get("src_ip", item.get("SrcAddr", "—")),
                "Destination": item.get("dst_ip", item.get("DstAddr", "—")),
                "Source port": item.get("src_port", item.get("Sport", "—")),
                "Destination port": item.get("dst_port", item.get("Dport", "—")),
                "Protocol": item.get("protocol", item.get("Proto", "—")),
                "Packets": item.get("packet_count", item.get("TotPkts", "—")),
                "Bytes": item.get("byte_count", item.get("TotBytes", "—")),
                "Evidence score": item.get("evidence_score", "—"),
                "Label": item.get("Label", "—"),
            }
        )
    return pd.DataFrame(rows)


def _early_warning_or_rollout(sequence: list[list[float]], world_model: dict[str, Any]) -> dict[str, Any]:
    try:
        result = predict_early_warning(sequence)
        result["model_status"] = "TRAINED_LEGACY_LSTM_LOADED"
        result["fallback"] = False
        return result
    except (RuntimeError, FileNotFoundError, ModuleNotFoundError) as exc:
        first_step = world_model["rollout"][0]
        return {
            "probability": first_step["risk_probability"],
            "probability_percent": first_step["risk_probability_percent"],
            "threshold": first_step["threshold"],
            "warning": first_step["predicted_attack"],
            "label": (
                "FORECAST WARNING"
                if first_step["predicted_attack"]
                else "NORMAL"
            ),
            "model": world_model["model"],
            "model_status": "WORLD_MODEL_ROLLOUT_FALLBACK",
            "fallback": True,
            "fallback_reason": str(exc),
            "note": (
                "Legacy TensorFlow early-warning model is unavailable; "
                "displaying the trained PyTorch world-model T+1 rollout "
                "instead."
            ),
        }


def _latent_projection(world_model: dict[str, Any]) -> pd.DataFrame:
    latent_states = [
        world_model.get("current_latent", []),
        *world_model.get("latent_rollout", []),
    ]
    labels = [
        "Current",
        *[
            f"Future +{index}"
            for index in range(1, len(latent_states))
        ],
    ]

    if not latent_states or not latent_states[0]:
        return pd.DataFrame()

    frame = pd.DataFrame(latent_states)
    if len(frame) == 1:
        return pd.DataFrame(
            {
                "state": labels,
                "x": [0.0],
                "y": [0.0],
            }
        )

    projection = PCA(n_components=2).fit_transform(frame)
    return pd.DataFrame(
        {
            "state": labels,
            "x": projection[:, 0],
            "y": projection[:, 1],
        }
    )


def run_analysis(content: bytes, filename: str, scenario: int | None) -> dict[str, Any]:
    suffix = Path(filename).suffix.lower()
    if suffix not in {".csv", ".pcap", ".pcapng", ".cap"}:
        raise ValueError("Upload a CSV, PCAP, PCAPNG, or CAP file.")

    with tempfile.TemporaryDirectory(prefix="threatcast-demo-") as directory:
        path = Path(directory) / Path(filename).name
        path.write_bytes(content)

        if suffix == ".csv":
            prepared = prepare_uploaded_csv(path, scenario=scenario)
            source = "CSV"
        else:
            prepared = prepare_uploaded_pcap(path)
            source = "PCAP"

        frame = prepared["dataframe"]
        sequence_batch = _sequences(frame)
        latest_sequence = prepared["payload"]["sequence"]
        detected_scenario = _scenario_from(frame, scenario if source == "CSV" else None)

        # The existing rollout function reports T+1/T+2/T+3 for the latest
        # sequence. Reusing it over recent sequences creates the timeline.
        recent = sequence_batch[-60:]
        timeline = []
        first_index = len(frame) - len(recent)
        for offset, sequence in enumerate(recent):
            rollout = predict_world_model_batch([sequence])["rollout"]
            timestamp_index = first_index + offset
            timestamp = (
                str(frame["Timestamp"].iloc[timestamp_index])
                if "Timestamp" in frame.columns
                else str(timestamp_index + 1)
            )
            row: dict[str, Any] = {"Timestamp": timestamp}
            for point in rollout:
                row[point["horizon"]] = point["risk_probability"]
            timeline.append(row)

        world_model = predict_world_model_batch(sequence_batch)
        early_warning = _early_warning_or_rollout(latest_sequence, world_model)
        stage_prediction = predict_stage_with_evidence(
            latest_sequence, scenario=detected_scenario
        )
        explanation_result = explain_sequence(latest_sequence)

        flagged: list[dict[str, Any]] = []
        packet_summary = None
        if source == "PCAP":
            packet_summary = analyze_pcap_attribution(path, limit=100)
            flagged = packet_summary.get("flagged_flows", [])
        else:
            columns = set(frame.columns)
            if {"SrcAddr", "DstAddr"}.issubset(columns):
                flagged = get_flagged_flows(str(path), limit=100)

        return {
            "source": source,
            "frame": frame,
            "scenario": detected_scenario,
            "timeline": pd.DataFrame(timeline).set_index("Timestamp"),
            "world_model": world_model,
            "early_warning": early_warning,
            "model_status": {
                "world_model": world_model.get("model_status", "UNKNOWN"),
                "early_warning": early_warning.get("model_status", "UNKNOWN"),
            },
            "stage_prediction": stage_prediction,
            "mitre_stages": (
                get_scenario_stages(detected_scenario) if detected_scenario else []
            ),
            "primary_stage": (
                get_primary_stage(detected_scenario) if detected_scenario else None
            ),
            "shap": explanation_result,
            "flagged": flagged,
            "packet_summary": packet_summary,
        }


def main() -> None:
    st.set_page_config(
        page_title="ThreatCast-AI Offline Demo",
        page_icon="🛡️",
        layout="wide",
    )
    st.title("ThreatCast-AI")
    st.caption("Offline infiltration-risk forecasting · local models · no external API calls")

    scenario_choice = st.sidebar.selectbox(
        "CTU13 scenario (CSV only)",
        options=["Auto-detect", *range(1, 14)],
        help="PCAP captures have no CTU13 scenario identifier.",
    )
    selected_scenario = None if scenario_choice == "Auto-detect" else int(scenario_choice)
    uploaded = st.file_uploader("Upload PCAP or CSV", type=["csv", "pcap", "pcapng", "cap"])

    if uploaded and st.button("Run ThreatCast analysis", type="primary", use_container_width=True):
        try:
            with st.spinner("Running local inference, rollout, MITRE mapping, and explainability..."):
                st.session_state["analysis"] = run_analysis(
                    uploaded.getvalue(), uploaded.name, selected_scenario
                )
        except Exception as exc:
            st.exception(exc)

    result = st.session_state.get("analysis")
    if result is None:
        st.info("Upload a CTU13-compatible CSV or a packet capture to begin.")
        st.stop()

    rollout = result["world_model"]["rollout"]
    metrics = st.columns(4)
    metrics[0].metric("Input", result["source"])
    metrics[1].metric("Temporal states", len(result["frame"]))
    metrics[2].metric("Scenario", result["scenario"] or "Unknown")
    metrics[3].metric(
        "Current forecast risk",
        f"{result['early_warning']['probability_percent']:.2f}%",
        result["early_warning"]["label"],
    )
    if result["early_warning"].get("fallback"):
        st.warning(result["early_warning"]["note"])

    st.subheader("Infiltration probability timeline")
    st.line_chart(result["timeline"], y=["T+1", "T+2", "T+3"])

    st.subheader("World-model future rollout")
    rollout_frame = pd.DataFrame(rollout)
    primary_stage = result["stage_prediction"]["primary_stage"]["name"]
    stage_confidence = result["stage_prediction"]["primary_stage"]["probability_percent"]
    rollout_frame["stage"] = primary_stage
    rollout_frame["stage_confidence_percent"] = stage_confidence
    st.dataframe(rollout_frame, hide_index=True, use_container_width=True)

    latent_projection = _latent_projection(result["world_model"])
    if not latent_projection.empty:
        st.subheader("Latent State Projection")
        st.scatter_chart(
            latent_projection,
            x="x",
            y="y",
            color="state",
            use_container_width=True,
        )

    st.subheader("Flagged flows")
    if result["flagged"]:
        st.dataframe(_flow_rows(result["flagged"]), hide_index=True, use_container_width=True)
    elif result["source"] == "CSV":
        timeline = result["timeline"].reset_index()
        thresholds = {item["horizon"]: item["threshold"] for item in rollout}
        flagged_states = timeline[
            timeline.apply(
                lambda row: any(row[horizon] >= threshold for horizon, threshold in thresholds.items()),
                axis=1,
            )
        ]
        st.caption("This aggregated CSV has no flow identities; flagged temporal states are shown.")
        st.dataframe(flagged_states, hide_index=True, use_container_width=True)
    else:
        st.success("No flows crossed the deterministic packet-evidence threshold.")

    st.subheader("MITRE ATT&CK stage annotations")
    left, right = st.columns(2)
    with left:
        st.markdown("**Weakly supervised model output**")
        probabilities = result["stage_prediction"].get("probabilities", {})
        numeric_probabilities = {
            stage: values["probability"]
            for stage, values in probabilities.items()
            if isinstance(values, dict) and "probability" in values
        }
        if numeric_probabilities:
            st.bar_chart(pd.Series(numeric_probabilities, name="Probability"))
        st.json(result["stage_prediction"])
    with right:
        st.markdown("**Documented CTU13 interpretation**")
        if result["scenario"]:
            st.write(f"Primary stage: {result['primary_stage']}")
            st.dataframe(pd.DataFrame(result["mitre_stages"]), hide_index=True, use_container_width=True)
        else:
            st.info("MITRE scenario annotations require a CTU13 scenario identifier.")

    st.subheader("Prediction explainability")
    contributions = pd.DataFrame(result["shap"]["feature_contributions"])
    chart = contributions.set_index("feature")["shap_value"].sort_values()
    st.bar_chart(chart, horizontal=True)
    st.dataframe(contributions, hide_index=True, use_container_width=True)
    st.caption(result["shap"]["note"])


if __name__ == "__main__":
    main()
