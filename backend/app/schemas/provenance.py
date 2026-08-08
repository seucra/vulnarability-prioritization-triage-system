"""
Research Provenance & Metadata Schemas
Repository: seucra/vulnarability-prioritization-triage-system
"""

from typing import Dict, List, Any
from pydantic import BaseModel, Field


class DatasetFreezeManifest(BaseModel):
    freeze_date: str = Field("2026-07-26", description="Date dataset was frozen")
    total_canonical_cves: int = 366547
    cvss_v31_scored_cves: int = 227694
    cisa_kev_cves: int = 1647
    epss_records: int = 348900
    cwe_mapping_cves: int = 265215
    cpe_mapping_cves: int = 306193


class TemporalPartitionsSchema(BaseModel):
    train_period: str = "2002–2022 (203,652 CVEs; 1,029 KEV positive)"
    validation_period: str = "2023–2024 (71,653 CVEs; 324 KEV positive)"
    test_period: str = "2025–2026 (91,242 CVEs; 294 KEV positive)"
    partition_discipline: str = "Publication-year split. Zero cross-year shuffling. TEST set remained untouched during hyperparameter selection."


class ModelProvenanceSchema(BaseModel):
    experiment_id: str
    target_variable: str
    prediction_point: str
    primary_metric: str
    baseline_performance: str
    nonlinear_performance: str
    relative_improvement: str


class ResearchProvenanceResponse(BaseModel):
    repository_name: str = "seucra/vulnarability-prioritization-triage-system"
    phase: str = "Phase 4 — Application / Backend Layer"
    dataset_freeze_manifest: DatasetFreezeManifest
    temporal_partitions: TemporalPartitionsSchema
    epss_snapshot_metadata: Dict[str, str] = Field(
        default_factory=lambda: {
            "snapshot_date": "2026-07-16T12:03:48Z",
            "model_version": "v2026.06.15",
            "retrospective_leakage_warning": "Static EPSS snapshot access inflates test PR-AUC by 11.49x (0.0288 -> 0.3315). Excluded from publication-time B2 model."
        }
    )
    phase_3_experiments: List[ModelProvenanceSchema]
    research_limitations: List[str]
