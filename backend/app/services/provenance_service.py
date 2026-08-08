"""
Provenance Service Layer
Repository: seucra/vulnarability-prioritization-triage-system
"""

from backend.app.config import settings
from backend.app.core.database import db_engine
from backend.app.schemas.provenance import (
    DatasetFreezeManifest,
    ModelProvenanceSchema,
    ResearchProvenanceResponse,
    TemporalPartitionsSchema,
)


class ProvenanceService:
    @staticmethod
    def get_provenance() -> ResearchProvenanceResponse:
        db_stats = db_engine.get_dataset_stats()
        
        manifest = DatasetFreezeManifest(
            freeze_date=settings.DATASET_FREEZE_DATE,
            total_canonical_cves=db_stats["total_vulnerabilities"],
            cvss_v31_scored_cves=db_stats["cvss_v31_scored_vulnerabilities"],
            cisa_kev_cves=db_stats["cisa_kev_records"],
            epss_records=db_stats["epss_records"],
            cwe_mapping_cves=265215,
            cpe_mapping_cves=306193,
        )
        
        partitions = TemporalPartitionsSchema()
        
        exp_a1 = ModelProvenanceSchema(
            experiment_id="EXP-A1",
            target_variable="cvss_v31_base_score",
            prediction_point="Pre-Scoring (Disclosure / Early Description)",
            primary_metric="MAE (Lower is better)",
            baseline_performance="1.0954 CVSS points (Ridge Regression, alpha=10)",
            nonlinear_performance="0.9750 CVSS points (XGBoost Regressor)",
            relative_improvement="-10.99% Relative Error Reduction (MAE -0.1204 points)"
        )
        
        exp_b2 = ModelProvenanceSchema(
            experiment_id="EXP-B2 (Primary)",
            target_variable="is_kev (CISA KEV Catalog Membership)",
            prediction_point="CVE Publication / Initial Triage (EPSS Excluded)",
            primary_metric="PR-AUC (Higher is better)",
            baseline_performance="0.02077 (Logistic Regression, C=10)",
            nonlinear_performance="0.02884 (XGBoost Classifier)",
            relative_improvement="+38.85% PR-AUC Uplift (8.96x vs Random Baseline 0.00322)"
        )
        
        exp_b1 = ModelProvenanceSchema(
            experiment_id="EXP-B1 (Retrospective Sensitivity)",
            target_variable="is_kev (Retrospective EPSS Snapshot Sensitivity)",
            prediction_point="RETROSPECTIVE SNAPSHOT (Uses 2026-07-16 EPSS)",
            primary_metric="PR-AUC (Retrospective Leakage Audit)",
            baseline_performance="0.29481 (Logistic Regression)",
            nonlinear_performance="0.33153 (XGBoost Classifier)",
            relative_improvement="11.49x Retrospective Leakage Inflation (PR-AUC +0.30269)"
        )
        
        exp_c1 = ModelProvenanceSchema(
            experiment_id="EXP-C1",
            target_variable="Prioritization Queue Rank Order",
            prediction_point="Decision-Support Simulation across Asset Tiers 1-4",
            primary_metric="Top-100 Queue Jaccard Overlap Ratio",
            baseline_performance="S_linear (Project-controlled equal weights baseline)",
            nonlinear_performance="S_nonlinear (Multiplicative interactive surface, alpha=1.0, beta=1.5)",
            relative_improvement="Top-100 Jaccard Overlap = 0.005 (Disrupts binary KEV ceiling)"
        )
        
        limitations = [
            "Static EPSS Snapshot Limitation: EPSS dataset is a single static snapshot (2026-07-16). Historical EPSS trajectories were unavailable.",
            "Synthetic Asset Criticality Context: Enterprise asset criticality tiers (0.25, 0.50, 0.75, 1.00) are controlled decision-support inputs, not observed enterprise ground truth.",
            "Unobserved Exploitation Label Incompleteness: Non-KEV CVEs (y=0) represent uncataloged or unobserved exploitation, not guaranteed non-exploitation.",
            "CPE Applicability Coverage: 16.47% of canonical CVEs lack structured CPE applicability nodes."
        ]
        
        return ResearchProvenanceResponse(
            repository_name=settings.REPOSITORY_NAME,
            phase="Phase 4 — Application / Backend Layer",
            dataset_freeze_manifest=manifest,
            temporal_partitions=partitions,
            phase_3_experiments=[exp_a1, exp_b2, exp_b1, exp_c1],
            research_limitations=limitations
        )


provenance_service = ProvenanceService()
