from __future__ import annotations

from pathlib import Path
from typing import Any

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

from backend.ml.pcap_attribution import (
    analyze_pcap_attribution,
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


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/api/world-model",
    tags=["World Model"],
)


# ============================================================
# CONSTANTS
# ============================================================

CSV_SUFFIXES = {
    ".csv",
}

PCAP_SUFFIXES = {
    ".pcap",
    ".pcapng",
    ".cap",
}

WORLD_MODEL_SUFFIXES = (
    CSV_SUFFIXES
    | PCAP_SUFFIXES
)


# ============================================================
# HELPERS
# ============================================================

def _validate_scenario(
    scenario: int | None,
) -> None:

    if (
        scenario is not None
        and not 1 <= scenario <= 13
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "CTU13 scenario must be "
                "between 1 and 13."
            ),
        )


def _detect_scenario(
    dataframe,
    scenario: int | None,
) -> int | None:

    # Explicit scenario always wins.

    if scenario is not None:
        return int(scenario)

    if (
        "Scenario" in dataframe.columns
        and len(dataframe) > 0
    ):

        try:

            detected = int(
                dataframe[
                    "Scenario"
                ].iloc[-1]
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
    allowed_suffixes: set[str],
) -> tuple[Path, Path]:

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No filename supplied.",
        )

    suffix = Path(
        file.filename
    ).suffix.lower()

    if suffix not in allowed_suffixes:

        allowed = ", ".join(
            sorted(
                allowed_suffixes
            )
        )

        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported file type. "
                f"Allowed: {allowed}"
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
        / Path(
            file.filename
        ).name
    )

    return (
        temp_path,
        upload_dir,
    )


def _prepare_uploaded_input(
    path: Path,
    scenario: int | None = None,
) -> dict[str, Any]:

    suffix = path.suffix.lower()

    # --------------------------------------------------------
    # CSV
    # --------------------------------------------------------

    if suffix == ".csv":

        result = prepare_uploaded_csv(
            path,
            scenario=scenario,
        )

        result[
            "input_source"
        ] = "csv"

        result[
            "packet_evidence"
        ] = None

        result[
            "pcap_metadata"
        ] = None

        return result

    # --------------------------------------------------------
    # PCAP
    # --------------------------------------------------------

    if suffix in PCAP_SUFFIXES:

        # A CTU13 scenario number cannot be inferred from an
        # arbitrary raw PCAP, so do not silently attach one.

        if scenario is not None:

            raise HTTPException(
                status_code=400,
                detail=(
                    "The scenario parameter is only "
                    "supported for CTU13 CSV input. "
                    "Raw PCAP input does not contain "
                    "a CTU13 scenario label."
                ),
            )

        result = prepare_uploaded_pcap(
            path
        )

        result[
            "input_source"
        ] = "pcap"

        return result

    raise HTTPException(
        status_code=400,
        detail=(
            "Unsupported world-model input. "
            "Use CSV, PCAP, PCAPNG, or CAP."
        ),
    )


def _build_world_model_sequences(
    dataframe,
) -> list[list[list[float]]]:

    if len(dataframe) < SEQUENCE_LENGTH:

        raise ValueError(
            f"At least "
            f"{SEQUENCE_LENGTH} temporal states "
            f"are required. "
            f"Received {len(dataframe)}."
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
            end_index
            - SEQUENCE_LENGTH
        )

        sequence = values[
            start_index:end_index
        ]

        sequences.append(
            sequence.tolist()
        )

    return sequences


# ============================================================
# DOCUMENTED ATT&CK INTERPRETATION
# ============================================================

@router.get(
    "/stage/{scenario}"
)
def get_stage(
    scenario: int,
):
    """
    Return the documented CTU13 activity
    interpretation and the trained weakly-
    supervised auxiliary stage prediction.
    """

    _validate_scenario(
        scenario
    )

    stages = get_scenario_stages(
        scenario
    )

    primary = get_primary_stage(
        scenario
    )

    try:

        dataset_path = (
            Path("data")
            / "CTU13"
            / "all_network_states.csv"
        )

        if not dataset_path.exists():

            raise FileNotFoundError(
                "CTU13 dataset not found: "
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

        trained_prediction = (
            predict_stage_with_evidence(
                payload[
                    "sequence"
                ],
                scenario=scenario,
            )
        )

        return {
            "success": True,

            "scenario": scenario,

            "primary_stage": primary,

            "stages": stages,

            "trained_stage_prediction": (
                trained_prediction
            ),

            "source": (
                "CTU13 documented activity "
                "interpretation + frozen "
                "weakly-supervised stage head"
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

            "states_used": len(
                dataframe
            ),

            "sequence_length": (
                SEQUENCE_LENGTH
            ),

            "note": (
                "CTU13 does not provide "
                "timestamp-level ground-truth "
                "MITRE ATT&CK labels. Stage "
                "predictions are therefore "
                "weakly supervised."
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

@router.get(
    "/stage-model-info"
)
def stage_model_info():

    try:

        return {
            "success": True,
            **get_stage_model_info(),
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load stage model "
                f"information: {exc}"
            ),
        ) from exc


# ============================================================
# PRODUCTION LSTM MODEL INFORMATION
# ============================================================

@router.get(
    "/model-info"
)
def model_info():

    return {
        "model": (
            "CTU13 LSTM Early Warning"
        ),

        "sequence_length": (
            SEQUENCE_LENGTH
        ),

        "feature_count": (
            len(FEATURE_NAMES)
        ),

        "features": FEATURE_NAMES,

        "input_format": (
            "5 temporal states × "
            "12 features"
        ),

        "state_duration": (
            "30 seconds"
        ),

        "temporal_context": (
            "150 seconds"
        ),

        "warning_threshold": 0.08,
    }


# ============================================================
# CSV -> PRODUCTION LSTM
# ============================================================

@router.post(
    "/csv"
)
async def run_csv_inference(
    file: UploadFile = File(...),
    scenario: int | None = None,
):

    _validate_scenario(
        scenario
    )

    temp_path, _ = _save_upload(
        file,
        CSV_SUFFIXES,
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

            "input_source": "csv",

            "filename": file.filename,

            "scenario": (
                detected_scenario
            ),

            "states": len(
                dataframe
            ),

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
                "Inference uses the "
                "existing CTU13 LSTM "
                "model and scaler."
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
# WORLD MODEL RISK
# ============================================================

@router.post(
    "/risk"
)
async def world_model_risk(
    file: UploadFile = File(...),
    scenario: int | None = None,
):

    _validate_scenario(
        scenario
    )

    temp_path, _ = _save_upload(
        file,
        WORLD_MODEL_SUFFIXES,
    )

    try:

        # ----------------------------------------------------
        # Save upload
        # ----------------------------------------------------

        content = await file.read()

        temp_path.write_bytes(
            content
        )

        # ----------------------------------------------------
        # Prepare CSV or PCAP
        # ----------------------------------------------------

        result = _prepare_uploaded_input(
            temp_path,
            scenario=scenario,
        )

        dataframe = result[
            "dataframe"
        ]

        payload = result[
            "payload"
        ]

        input_source = result[
            "input_source"
        ]

        packet_evidence = result.get(
            "packet_evidence"
        )

        pcap_metadata = result.get(
            "pcap_metadata"
        )

        # ----------------------------------------------------
        # Scenario
        # ----------------------------------------------------

        detected_scenario = (
            _detect_scenario(
                dataframe,
                scenario,
            )
        )

        # ----------------------------------------------------
        # Build chronological 5-state
        # windows.
        #
        # The world-model risk inference requires
        # the complete uploaded temporal sequence
        # because scenario-adaptive calibration
        # operates over all available windows.
        # ----------------------------------------------------

        sequences = (
            _build_world_model_sequences(
                dataframe
            )
        )

        # ----------------------------------------------------
        # Risk world model
        # ----------------------------------------------------

        world_model_result = (
            predict_world_model_batch(
                sequences
            )
        )

        # ----------------------------------------------------
        # Stage prediction
        #
        # For both CSV and PCAP, the stage head receives
        # the canonical latest normalized 5 × 12 sequence.
        # ----------------------------------------------------

        stage_prediction = (
            predict_stage_with_evidence(
                payload[
                    "sequence"
                ],
                scenario=detected_scenario,
            )
        )

        # ----------------------------------------------------
        # Documented CTU13 interpretation
        # ----------------------------------------------------

        stage = _get_stage(
            detected_scenario
        )

        # ----------------------------------------------------
        # Packet / port / flag attribution
        #
        # ONLY raw PCAP gets concrete packet/flow
        # attribution.
        #
        # CSV retains its existing feature evidence.
        # ----------------------------------------------------

        packet_attribution = None

        if input_source == "pcap":

            packet_attribution = (
                analyze_pcap_attribution(
                    temp_path,
                    limit=20,
                )
            )

        # ----------------------------------------------------
        # Explainability
        # ----------------------------------------------------

        explainability = {
            "available": True,

            "method": (
                "feature-level telemetry evidence"
                + (
                    " + deterministic "
                    "PCAP packet/flow attribution"
                    if input_source == "pcap"
                    else ""
                )
            ),

            "feature_evidence": (
                stage_prediction[
                    "evidence"
                ]
            ),

            "raw_port_information_available": (
                input_source == "pcap"
            ),

            "port_attribution": (
                packet_attribution
                if input_source == "pcap"
                else None
            ),

            "packet_evidence_available": (
                input_source == "pcap"
            ),

            "packet_evidence": (
                packet_evidence
                if input_source == "pcap"
                else None
            ),

            "note": (
                "For PCAP input, source/destination "
                "IP addresses, source/destination "
                "ports, transport protocol, and "
                "TCP flag observations are retained "
                "from the raw capture and exposed "
                "as deterministic flow-level evidence. "
                "These fields are not additional "
                "trained world-model inputs."
            ),
        }

        # ----------------------------------------------------
        # Return
        # ----------------------------------------------------

        return {
            "success": True,

            "pipeline": (
                (
                    "PCAP → 30-second temporal "
                    "aggregation → CTU13 Risk "
                    "World Model + Stage Head"
                )
                if input_source == "pcap"
                else
                (
                    "CSV → CTU13 Risk World "
                    "Model + Stage Head"
                )
            ),

            "input_source": input_source,

            "filename": file.filename,

            "scenario": detected_scenario,

            "pcap_metadata": (
                pcap_metadata
            ),

            "packet_evidence": (
                packet_evidence
            ),

            "packet_attribution": (
                packet_attribution
            ),

            "states": len(
                dataframe
            ),

            "sequence_length": (
                SEQUENCE_LENGTH
            ),

            "feature_count": (
                len(FEATURE_NAMES)
            ),

            "features": FEATURE_NAMES,

            "input": payload,

            "world_model": (
                world_model_result
            ),

            "stage_interpretation": stage,

            "trained_stage_prediction": (
                stage_prediction
            ),

            "explainability": (
                explainability
            ),

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
# EXISTING FLAGGED-FLOW ENDPOINT
# ============================================================

@router.get(
    "/flagged-flows"
)
def flagged_flows(
    path: str,
    limit: int = 100,
):

    if (
        limit < 1
        or limit > 1000
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "limit must be between "
                "1 and 1000."
            ),
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