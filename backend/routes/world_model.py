from __future__ import annotations

from pathlib import Path

from fastapi import (
    APIRouter,
    File,
    HTTPException,
    UploadFile,
)

from backend.data.flagged_flows import (
    get_flagged_flows,
)

from backend.ml.inference import (
    FEATURE_NAMES,
    SEQUENCE_LENGTH,
    predict_early_warning,
)

from backend.ml.input_pipeline import (
    prepare_uploaded_csv,
)

from backend.ml.pcap_adapter import (
    prepare_uploaded_pcap,
)

from world_model.attack_stage import (
    get_primary_stage,
    get_scenario_stages,
)

from world_model.ctu13_risk_inference import (
    predict_world_model_batch,
)

from world_model.stage_inference import (
    get_stage_model_info,
    predict_stage_with_evidence,
)


router = APIRouter(
    prefix="/api/world-model",
    tags=["World Model"],
)


# ============================================================
# HELPERS
# ============================================================

def _validate_scenario(
    scenario: int | None,
) -> None:
    if scenario is not None and not 1 <= scenario <= 13:
        raise HTTPException(
            status_code=400,
            detail="CTU13 scenario must be between 1 and 13.",
        )


def _detect_scenario(
    dataframe,
    scenario: int | None,
) -> int | None:
    """
    Resolve the scenario from the explicit query parameter
    or from the uploaded dataframe.

    Explicit scenario always takes priority.
    """

    if scenario is not None:
        return int(scenario)

    if (
        "Scenario" in dataframe.columns
        and len(dataframe) > 0
    ):
        try:
            detected = int(
                dataframe["Scenario"].iloc[-1]
            )

            if 1 <= detected <= 13:
                return detected

        except (
            TypeError,
            ValueError,
        ):
            pass

    return None


def _get_stage(
    scenario: int | None,
) -> dict | None:

    if scenario is None:
        return None

    if not 1 <= scenario <= 13:
        return None

    return get_primary_stage(
        scenario
    )


def _save_upload(
    file: UploadFile,
    allowed_suffixes: set[str] | None = None,
) -> tuple[Path, Path]:

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No filename supplied.",
        )

    suffix = Path(
        file.filename
    ).suffix.lower()

    if allowed_suffixes is None:
        allowed_suffixes = {
            ".csv",
            ".pcap",
            ".pcapng",
            ".cap",
        }

    if suffix not in allowed_suffixes:
        allowed_text = ", ".join(
            sorted(allowed_suffixes)
        )

        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported input format. "
                f"Accepted formats: {allowed_text}."
            ),
        )

    upload_dir = (
        Path("backend")
        / "data"
        / "uploads"
    )

    upload_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_path = (
        upload_dir
        / Path(file.filename).name
    )

    return temp_path, upload_dir


def _prepare_uploaded_input(
    path: Path,
    scenario: int | None = None,
) -> tuple[dict, str]:
    """
    Convert CSV or PCAP-family input into the existing
    world-model inference representation.

    CSV keeps the existing CTU13 input pipeline unchanged.
    PCAP/PCAPNG/CAP is converted to 30-second temporal
    states containing the same 12 model features.
    """

    suffix = path.suffix.lower()

    if suffix == ".csv":
        result = prepare_uploaded_csv(
            path,
            scenario=scenario,
        )
        return result, "csv"

    if suffix in {
        ".pcap",
        ".pcapng",
        ".cap",
    }:
        if scenario is not None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "The scenario parameter is only valid for CSV "
                    "CTU13 input. PCAP input does not contain a "
                    "CTU13 scenario identifier."
                ),
            )

        result = prepare_uploaded_pcap(
            path,
        )
        return result, "pcap"

    raise HTTPException(
        status_code=400,
        detail=(
            "Unsupported input format. "
            "Accepted formats: .csv, .pcap, .pcapng, .cap."
        ),
    )


def _build_world_model_sequences(
    dataframe,
) -> list[list[list[float]]]:

    if len(dataframe) < SEQUENCE_LENGTH:
        raise ValueError(
            f"At least {SEQUENCE_LENGTH} temporal states "
            f"are required. Received {len(dataframe)}."
        )

    values = (
        dataframe[
            FEATURE_NAMES
        ]
        .astype(float)
        .to_numpy()
    )

    sequences = []

    for end_index in range(
        SEQUENCE_LENGTH,
        len(values) + 1,
    ):

        start_index = (
            end_index - SEQUENCE_LENGTH
        )

        sequence = values[
            start_index:end_index
        ]

        sequences.append(
            sequence.tolist()
        )

    return sequences


# ============================================================
# ATT&CK ACTIVITY INTERPRETATION
# ============================================================

@router.get("/stage/{scenario}")
def get_stage(
    scenario: int,
):
    """
    Return both:

    1. The documented CTU13 activity -> ATT&CK interpretation.
    2. The trained weakly-supervised stage prediction.

    IMPORTANT:
    CTU13 does not contain timestamp-level ground-truth
    MITRE ATT&CK tactic labels.

    Therefore the trained stage head is explicitly reported
    as weakly supervised rather than ground-truth supervised.
    """

    _validate_scenario(
        scenario
    )

    # --------------------------------------------------------
    # Existing documented CTU13 interpretation
    # --------------------------------------------------------

    stages = get_scenario_stages(
        scenario
    )

    primary = get_primary_stage(
        scenario
    )

    # --------------------------------------------------------
    # Build a real 5-state sequence from the canonical CTU13
    # dataset for stage inference.
    #
    # The stage endpoint is scenario-based, so this endpoint
    # uses the latest available five states from that scenario.
    # --------------------------------------------------------

    try:

        dataset_path = (
            Path("data")
            / "CTU13"
            / "all_network_states.csv"
        )

        if not dataset_path.exists():
            raise FileNotFoundError(
                f"CTU13 dataset not found: "
                f"{dataset_path}"
            )

        result = prepare_uploaded_csv(
            dataset_path,
            scenario=scenario,
        )

        dataframe = result[
            "dataframe"
        ]

        payload = result[
            "payload"
        ]

        sequence = payload[
            "sequence"
        ]

        trained_prediction = (
            predict_stage_with_evidence(
                sequence,
                scenario=scenario,
            )
        )

        return {
            "success": True,
            "scenario": scenario,

            # Existing documented interpretation.
            "primary_stage": primary,
            "stages": stages,

            # New trained prediction.
            "trained_stage_prediction": (
                trained_prediction
            ),

            "source": (
                "CTU13 documented activity "
                "interpretation + frozen weakly-supervised "
                "stage head"
            ),

            "trained_stage_classifier": True,

            "supervision": (
                "weakly supervised"
            ),

            "ground_truth_timestamped_mitre_labels": (
                False
            ),

            "scenario_13_used_for_training": (
                False
            ),

            "scenario_13_used_for_model_selection": (
                False
            ),

            "scenario_13_used_for_threshold_selection": (
                False
            ),

            "note": (
                "The stage head predicts Discovery, "
                "Command and Control, and Impact from "
                "the frozen 64-D CTU13 world-model latent. "
                "CTU13 does not provide timestamp-level "
                "ground-truth MITRE ATT&CK labels, so "
                "stage predictions are weakly supervised "
                "and should not be described as "
                "ground-truth MITRE classification."
            ),

            "states_used": len(
                dataframe
            ),

            "sequence_length": (
                SEQUENCE_LENGTH
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=(
                "Stage inference failed: "
                f"{exc}"
            ),
        ) from exc


# ============================================================
# STAGE MODEL INFORMATION
# ============================================================

@router.get("/stage-model-info")
def stage_model_info():
    """
    Return metadata for the trained weakly-supervised
    MITRE stage head.
    """

    try:

        return {
            "success": True,
            **get_stage_model_info(),
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load stage model information: "
                f"{exc}"
            ),
        ) from exc


# ============================================================
# PRODUCTION LSTM MODEL INFORMATION
# ============================================================

@router.get("/model-info")
def model_info():
    return {
        "model": "CTU13 LSTM Early Warning",
        "sequence_length": SEQUENCE_LENGTH,
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "input_format": (
            "5 temporal states × 12 features"
        ),
        "state_duration": "30 seconds",
        "temporal_context": "150 seconds",
        "warning_threshold": 0.08,
    }


# ============================================================
# CSV -> PRODUCTION LSTM INFERENCE
# ============================================================

@router.post("/csv")
async def run_csv_inference(
    file: UploadFile = File(...),
    scenario: int | None = None,
):
    """
    Run the existing production CTU13 LSTM on an uploaded CSV.
    """

    _validate_scenario(
        scenario
    )

    temp_path, _ = _save_upload(
        file,
        allowed_suffixes={".csv"},
    )

    try:

        content = await file.read()

        temp_path.write_bytes(
            content
        )

        result = prepare_uploaded_csv(
            temp_path,
            scenario=scenario,
        )

        dataframe = result[
            "dataframe"
        ]

        payload = result[
            "payload"
        ]

        prediction = predict_early_warning(
            payload[
                "sequence"
            ]
        )

        detected_scenario = (
            _detect_scenario(
                dataframe,
                scenario,
            )
        )

        stage = _get_stage(
            detected_scenario
        )

        return {
            "success": True,
            "pipeline": (
                "CSV → CTU13 LSTM"
            ),
            "filename": file.filename,
            "scenario": detected_scenario,
            "states": len(dataframe),
            "sequence_length": (
                SEQUENCE_LENGTH
            ),
            "features": FEATURE_NAMES,
            "prediction": prediction,
            "stage_interpretation": stage,
            "input": {
                "timestamps": payload[
                    "timestamps"
                ],
                "sequence": payload[
                    "sequence"
                ],
            },
            "research_note": (
                "Inference uses the existing CTU13 "
                "LSTM model and scaler. Attack labels "
                "are not used as model inputs."
            ),
        }

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    finally:

        try:
            temp_path.unlink(
                missing_ok=True
            )
        except Exception:
            pass


# ============================================================
# CSV / PCAP -> TRAINED WORLD MODEL RISK ROLLOUT
# ============================================================

@router.post("/risk")
async def world_model_risk(
    file: UploadFile = File(...),
    scenario: int | None = None,
):
    """
    Run the trained CTU13 risk world model.

    CSV input keeps the existing CTU13 pipeline.
    PCAP/PCAPNG/CAP input is converted into the same
    30-second temporal feature representation first.

    The complete uploaded input is converted into
    chronological 5-state windows.

    Raw risk logits from all windows are collected first
    so the frozen scenario-adaptive calibration can calculate
    the scenario score distribution.

    The endpoint returns:

        - calibrated T+1 / T+2 / T+3 risk
        - trained stage prediction
        - MITRE interpretation
        - feature-level evidence
        - packet-level evidence when the source is PCAP
    """

    _validate_scenario(
        scenario
    )

    temp_path, _ = _save_upload(
        file,
        allowed_suffixes={
            ".csv",
            ".pcap",
            ".pcapng",
            ".cap",
        },
    )

    try:

        content = await file.read()

        temp_path.write_bytes(
            content
        )

        result, input_source = _prepare_uploaded_input(
            temp_path,
            scenario=scenario,
        )

        dataframe = result[
            "dataframe"
        ]

        payload = result[
            "payload"
        ]

        packet_evidence = result.get(
            "packet_evidence"
        )

        pcap_metadata = result.get(
            "pcap_metadata"
        )

        # --------------------------------------------------------
        # Scenario detection
        # --------------------------------------------------------

        detected_scenario = (
            _detect_scenario(
                dataframe,
                scenario,
            )
        )

        # --------------------------------------------------------
        # Risk-world-model sequences
        # --------------------------------------------------------

        sequences = (
            _build_world_model_sequences(
                dataframe
            )
        )

        world_model_result = (
            predict_world_model_batch(
                sequences
            )
        )

        # --------------------------------------------------------
        # Trained stage prediction on the latest 5-state history
        #
        # payload["sequence"] is the canonical 5 x 12 sequence
        # produced by the existing input pipeline or PCAP adapter.
        # --------------------------------------------------------

        stage_prediction = (
            predict_stage_with_evidence(
                payload[
                    "sequence"
                ],
                scenario=detected_scenario,
            )
        )

        # --------------------------------------------------------
        # Existing documented interpretation
        # --------------------------------------------------------

        stage = _get_stage(
            detected_scenario
        )

        # --------------------------------------------------------
        # Combined response
        # --------------------------------------------------------

        return {
            "success": True,

            "pipeline": (
                (
                    "PCAP → 30-second temporal aggregation → "
                    "CTU13 Risk World Model + Stage Head"
                )
                if input_source == "pcap"
                else (
                    "CSV → CTU13 Risk World Model "
                    "+ Stage Head"
                )
            ),

            "input_source": input_source,

            "filename": file.filename,

            "scenario": detected_scenario,

            "pcap_metadata": pcap_metadata,

            "packet_evidence": packet_evidence,

            "states": len(
                dataframe
            ),

            "sequence_length": (
                SEQUENCE_LENGTH
            ),

            "feature_count": len(
                FEATURE_NAMES
            ),

            "features": FEATURE_NAMES,

            "input": payload,

            # Existing calibrated risk rollout.
            "world_model": world_model_result,

            # Existing documented mapping.
            "stage_interpretation": stage,

            # Existing trained stage classifier.
            "trained_stage_prediction": (
                stage_prediction
            ),

            "explainability": {
                "available": True,

                "method": (
                    "feature-level telemetry evidence"
                ),

                "feature_evidence": (
                    stage_prediction[
                        "evidence"
                    ]
                ),

                "raw_port_information_available": (
                    False
                ),

                "port_attribution": None,

                "packet_evidence_available": (
                    input_source == "pcap"
                ),

                "packet_evidence": packet_evidence,

                "note": (
                    "CSV input exposes the existing "
                    "aggregated feature evidence. PCAP input "
                    "additionally exposes packet-level telemetry "
                    "such as TCP flags, destination-port diversity, "
                    "scan entropy, IP cardinality, packet size, "
                    "TTL, and TCP-window statistics. These packet "
                    "features are evidence fields and are not "
                    "additional trained model inputs."
                ),
            },

            "classifier_scope": {
                "trained_stage_classifier": True,

                "supervision": (
                    "weakly supervised"
                ),

                "ground_truth_timestamped_mitre_labels": (
                    False
                ),

                "scenario_13_used_for_training": (
                    False
                ),

                "scenario_13_used_for_model_selection": (
                    False
                ),

                "scenario_13_used_for_threshold_selection": (
                    False
                ),
            },
        }

    except HTTPException:
        raise

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    finally:

        try:
            temp_path.unlink(
                missing_ok=True
            )
        except Exception:
            pass


# ============================================================
# FLAGGED FLOW EVIDENCE
# ============================================================

@router.get("/flagged-flows")
def flagged_flows(
    path: str,
    limit: int = 100,
):
    """
    Return suspicious flow records from a CTU13
    .binetflow file.

    This remains separate from the aggregated
    world-model feature evidence.
    """

    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 1000.",
        )

    try:

        flows = get_flagged_flows(
            path,
            limit=limit,
        )

        return {
            "count": len(flows),
            "flows": flows,
        }

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
