"""
Prioritization Scoring Service (Linear Baseline vs Nonlinear Decision Surface)
Repository: seucra/vulnarability-prioritization-triage-system
"""

import numpy as np
from backend.app.config import settings
from backend.app.core.database import db_engine
from backend.app.schemas.batch_prioritization import (
    BatchItemInput,
    BatchItemResult,
    BatchPrioritizationRequest,
    BatchPrioritizationResponse,
    BatchSummaryKPI,
)
from backend.app.schemas.prioritization import (
    PrioritizationRequest,
    PrioritizationResponse,
    PrioritizationScoreDetail,
)


class ScoringService:
    @staticmethod
    def calculate_linear_score(x1: float, x2: float, x3: float, x4: float) -> float:
        """
        MODE 1 — Transparent Linear Baseline
        S_linear = 0.25*x1 + 0.25*x2 + 0.25*x3 + 0.25*x4
        Explicitly defined as: Project-controlled equal weights baseline.
        """
        w1, w2, w3, w4 = 0.25, 0.25, 0.25, 0.25
        return float(np.clip(w1 * x1 + w2 * x2 + w3 * x3 + w4 * x4, 0.0, 1.0))

    @staticmethod
    def calculate_nonlinear_score(x1: float, x2: float, x3: float, x4: float) -> float:
        """
        MODE 2 — Nonlinear Interactive Decision Surface
        S_nonlinear = x4 * [ 1 - (1 - x1)^(1 + alpha*x3) * (1 - x2)^(1 + beta*x3) ]
        with alpha = 1.0, beta = 1.5
        """
        alpha = settings.C1_ALPHA_KEV_SEVERITY_MULT # 1.0
        beta = settings.C1_BETA_KEV_THREAT_MULT    # 1.5
        
        x1_c = float(np.clip(x1, 0.0, 1.0))
        x2_c = float(np.clip(x2, 0.0, 1.0))
        x3_c = float(np.clip(x3, 0.0, 1.0))
        x4_c = float(np.clip(x4, 0.0, 1.0))
        
        sev_factor = (1.0 - x1_c) ** (1.0 + alpha * x3_c)
        threat_factor = (1.0 - x2_c) ** (1.0 + beta * x3_c)
        
        risk_core = 1.0 - (sev_factor * threat_factor)
        return float(np.clip(x4_c * risk_core, 0.0, 1.0))

    @classmethod
    def prioritize(cls, req: PrioritizationRequest) -> PrioritizationResponse:
        x1 = req.cvss_score / 10.0 # Normalized CVSS [0, 1]
        x2 = req.epss_score        # EPSS [0, 1]
        x3 = 1.0 if req.is_kev else 0.0 # KEV binary flag
        x4 = req.asset_criticality # Asset Criticality Tier weight [0.25 - 1.0]
        
        s_lin = cls.calculate_linear_score(x1, x2, x3, x4)
        s_nonlin = cls.calculate_nonlinear_score(x1, x2, x3, x4)
        
        # Categorize tier label
        if x4 <= 0.30:
            tier_name = "Tier 1 (Low Criticality: 0.25)"
        elif x4 <= 0.60:
            tier_name = "Tier 2 (Medium Criticality: 0.50)"
        elif x4 <= 0.85:
            tier_name = "Tier 3 (High Criticality: 0.75)"
        else:
            tier_name = "Tier 4 (Critical Infrastructure: 1.00)"
            
        inputs_dict = {
            "normalized_cvss_x1": round(x1, 4),
            "epss_probability_x2": round(x2, 4),
            "is_kev_x3": x3,
            "asset_criticality_x4": x4
        }
        
        detail_lin = PrioritizationScoreDetail(
            priority_score=round(s_lin, 4),
            scoring_mode="MODE 1 — Transparent Linear Baseline (Project-Controlled Equal Weights)",
            asset_criticality_tier=tier_name,
            asset_criticality_x4=x4,
            inputs=inputs_dict
        )
        
        detail_nonlin = PrioritizationScoreDetail(
            priority_score=round(s_nonlin, 4),
            scoring_mode="MODE 2 — Nonlinear Interactive Decision Surface (alpha=1.0, beta=1.5)",
            asset_criticality_tier=tier_name,
            asset_criticality_x4=x4,
            inputs=inputs_dict
        )
        
        return PrioritizationResponse(
            cve_id=req.cve_id,
            linear_baseline_mode_1=detail_lin,
            nonlinear_surface_mode_2=detail_nonlin,
        )

    @classmethod
    def prioritize_batch(cls, req: BatchPrioritizationRequest) -> BatchPrioritizationResponse:
        # Collect all requested CVE IDs
        cve_ids_to_fetch = [
            item.cve_id for item in req.items
            if item.cve_id and item.cve_id.strip()
        ]
        
        db_records = db_engine.get_vulnerabilities_by_ids(cve_ids_to_fetch)
        
        successful_items: List[BatchItemResult] = []
        error_items: List[BatchItemResult] = []
        
        for idx, item in enumerate(req.items):
            cve_id = item.cve_id
            asset_w = item.asset_criticality if item.asset_criticality is not None else req.default_asset_criticality
            
            if asset_w <= 0.30:
                tier_name = "Tier 1 (Low Criticality: 0.25)"
            elif asset_w <= 0.60:
                tier_name = "Tier 2 (Medium Criticality: 0.50)"
            elif asset_w <= 0.85:
                tier_name = "Tier 3 (High Criticality: 0.75)"
            else:
                tier_name = "Tier 4 (Critical Infrastructure: 1.00)"
                
            is_override = (
                item.cvss_score is not None or
                item.epss_score is not None or
                item.is_kev is not None
            )
            
            cvss_val = None
            epss_val = None
            kev_val = None
            
            if cve_id:
                record = db_records.get(cve_id.upper())
                if not record and not is_override:
                    error_items.append(BatchItemResult(
                        rank=99999,
                        cve_id=cve_id,
                        custom_label=item.custom_label,
                        asset_criticality=asset_w,
                        asset_criticality_tier=tier_name,
                        status="not_found",
                        error_message=f"CVE ID '{cve_id}' not found in system dataset",
                        is_analyst_override=False
                    ))
                    continue
                
                if record:
                    cvss_val = item.cvss_score if item.cvss_score is not None else record.get("cvss_v31_base_score")
                    epss_val = item.epss_score if item.epss_score is not None else record.get("epss_score")
                    kev_val = item.is_kev if item.is_kev is not None else record.get("is_kev")
                else:
                    cvss_val = item.cvss_score
                    epss_val = item.epss_score
                    kev_val = item.is_kev
            else:
                cvss_val = item.cvss_score
                epss_val = item.epss_score
                kev_val = item.is_kev
                
            if cvss_val is None or epss_val is None or kev_val is None:
                error_items.append(BatchItemResult(
                    rank=99999,
                    cve_id=cve_id,
                    custom_label=item.custom_label,
                    cvss_score=cvss_val,
                    epss_score=epss_val,
                    is_kev=kev_val,
                    asset_criticality=asset_w,
                    asset_criticality_tier=tier_name,
                    status="validation_error",
                    error_message="Item requires valid CVE ID or complete cvss_score, epss_score, and is_kev values",
                    is_analyst_override=is_override
                ))
                continue

            # Calculate scores
            x1 = cvss_val / 10.0
            x2 = epss_val
            x3 = 1.0 if kev_val else 0.0
            x4 = asset_w
            
            s_lin = cls.calculate_linear_score(x1, x2, x3, x4)
            s_nonlin = cls.calculate_nonlinear_score(x1, x2, x3, x4)
            shift = s_nonlin - s_lin
            
            successful_items.append(BatchItemResult(
                rank=1, # Re-assigned after sorting
                cve_id=cve_id,
                custom_label=item.custom_label,

                cvss_score=round(cvss_val, 1),
                epss_score=round(epss_val, 4),
                is_kev=bool(kev_val),
                asset_criticality=round(asset_w, 2),
                asset_criticality_tier=tier_name,
                linear_score=round(s_lin, 4),
                nonlinear_score=round(s_nonlin, 4),
                score_shift=round(shift, 4),
                status="success",
                error_message=None,
                is_analyst_override=is_override
            ))

        # Deterministic Sorting & Tie-Breaking
        is_mode2 = (req.primary_sort.lower() == "mode_2")
        is_desc = (req.sort_dir.lower() == "desc")
        
        def sort_key(res: BatchItemResult):
            primary_score = res.nonlinear_score if is_mode2 else res.linear_score
            primary_mult = -1.0 if is_desc else 1.0
            return (
                primary_mult * (primary_score if primary_score is not None else 0.0),
                -(res.cvss_score if res.cvss_score is not None else 0.0),
                -(res.epss_score if res.epss_score is not None else 0.0),
                -1 if res.is_kev else 0,
                (res.cve_id or res.custom_label or "").upper()
            )
            
        successful_items.sort(key=sort_key)
        
        # Assign 1-indexed rank
        for r_idx, item_res in enumerate(successful_items, start=1):
            item_res.rank = r_idx
            
        for r_idx, item_err in enumerate(error_items, start=len(successful_items) + 1):
            item_err.rank = r_idx

        all_items = successful_items + error_items

        # Compute Summary KPI Metrics
        total_req = len(req.items)
        total_proc = len(successful_items)
        total_err = len(error_items)
        
        high_prio_cnt = sum(1 for it in successful_items if (it.nonlinear_score or 0.0) >= 0.70)
        kev_cnt = sum(1 for it in successful_items if it.is_kev)
        
        mode2_scores = [it.nonlinear_score for it in successful_items if it.nonlinear_score is not None]
        avg_mode2 = round(float(np.mean(mode2_scores)), 4) if mode2_scores else 0.0
        
        shifts = [abs(it.score_shift) for it in successful_items if it.score_shift is not None]
        max_shift = round(float(max(shifts)), 4) if shifts else 0.0

        summary = BatchSummaryKPI(
            total_requested=total_req,
            total_processed=total_proc,
            total_errors=total_err,
            high_priority_count=high_prio_cnt,
            kev_count=kev_cnt,
            avg_mode_2_score=avg_mode2,
            max_score_shift=max_shift
        )
        
        return BatchPrioritizationResponse(
            total_requested=total_req,
            total_processed=total_proc,
            total_errors=total_err,
            primary_sort=req.primary_sort,
            sort_dir=req.sort_dir,
            summary=summary,
            items=all_items
        )


scoring_service = ScoringService()

