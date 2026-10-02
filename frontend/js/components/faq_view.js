/**
 * FAQ (Frequently Asked Questions) View Component
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

export function renderFaqView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Frequently Asked Questions</h2>
                <p class="section-desc">Academic background, canonical dataset characterization, machine learning methodology, and application usage.</p>
            </div>
            <span class="badge badge-neutral" style="font-size: 11px;">Research Documentation</span>
        </div>

        <div style="max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 20px;">
            <!-- Category 1: System Overview -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" style="font-size: 15px; margin: 0;">1. System Scope & Purpose</h3>
                </div>

                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <details class="disclosure" open>
                        <summary class="disclosure-summary">
                            <span>What is the Vulnerability Prioritization & Triage System (VTS)?</span>
                        </summary>
                        <div style="padding-top: 10px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                            VTS is an academic research and decision-support web application designed to evaluate machine learning estimation models (CVSS base scores and publication-time KEV risk) and combine them with enterprise asset criticality context for vulnerability triage.
                        </div>
                    </details>

                    <details class="disclosure">
                        <summary class="disclosure-summary">
                            <span>What core problem in vulnerability management does this research address?</span>
                        </summary>
                        <div style="padding-top: 10px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                            Organizations face an overwhelming volume of newly disclosed CVEs annually. Official NVD CVSS scoring often experiences disclosure lag (weeks to months), while EPSS scores and CISA KEV listings reflect post-publication observations. This system addresses pre-scoring estimation and publication-time threat risk prediction to enable immediate triage upon disclosure.
                        </div>
                    </details>

                    <details class="disclosure">
                        <summary class="disclosure-summary">
                            <span>Is this system intended as a live commercial cybersecurity platform?</span>
                        </summary>
                        <div style="padding-top: 10px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                            No. This software is an academic research prototype developed for reproducible scientific evaluation. It operates on a frozen, deterministic research dataset (366,547 CVEs) and static EPSS snapshot (2026-07-16) to ensure experimental reproducibility.
                        </div>
                    </details>
                </div>
            </div>

            <!-- Category 2: Machine Learning Methodology -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" style="font-size: 15px; margin: 0;">2. Machine Learning Methodology & Experiments</h3>
                </div>

                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <details class="disclosure" open>
                        <summary class="disclosure-summary">
                            <span>What is the purpose of Experiment EXP-A1?</span>
                        </summary>
                        <div style="padding-top: 10px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                            EXP-A1 evaluates pre-scoring CVSS v3.1 base score regression using initial text descriptions and CWE metadata available at publication time. Using an XGBoost regressor, EXP-A1 achieves a Mean Absolute Error (MAE) of 0.9750 on held-out 2025–2026 test disclosures (vs Ridge baseline: 1.0954, an 11.0% relative improvement).
                        </div>
                    </details>

                    <details class="disclosure">
                        <summary class="disclosure-summary">
                            <span>What is Experiment EXP-B2 and why are publication-time feature boundaries strictly enforced?</span>
                        </summary>
                        <div style="padding-top: 10px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                            EXP-B2 is a publication-time binary classifier predicting whether a newly disclosed vulnerability will eventually enter the CISA KEV catalog. Post-publication signals such as official CVSS scores or EPSS telemetry are strictly excluded during feature extraction to prevent historical data leakage (identified in retrospective experiment EXP-B1). EXP-B2 achieves a test PR-AUC of 0.02884 (~5.5× uplift over random baseline).
                        </div>
                    </details>

                    <details class="disclosure">
                        <summary class="disclosure-summary">
                            <span>What is the temporal evaluation partitioning protocol?</span>
                        </summary>
                        <div style="padding-top: 10px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                            To prevent temporal look-ahead leakage across disclosure years, the dataset is split strictly chronologically by publication year:
                            <strong>TRAIN:</strong> 2002–2022 (203,652 CVEs), <strong>VALIDATION:</strong> 2023–2024 (71,653 CVEs for hyperparameter selection), and <strong>TEST:</strong> 2025–2026 (91,242 CVEs held out untouched for final evaluation).
                        </div>
                    </details>

                    <details class="disclosure">
                        <summary class="disclosure-summary">
                            <span>How does SHAP explainability work in this system?</span>
                        </summary>
                        <div style="padding-top: 10px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                            SHAP (SHapley Additive exPlanations) TreeExplainer computes exact feature contribution values for individual tree ensemble predictions. Positive SHAP values indicate features increasing severity or KEV probability, while negative values indicate features reducing risk. SHAP values reflect model decision logic and do not imply physical execution causality.
                        </div>
                    </details>
                </div>
            </div>

            <!-- Category 3: Prioritization Engine -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" style="font-size: 15px; margin: 0;">3. Prioritization Surfaces & Asset Context</h3>
                </div>

                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <details class="disclosure" open>
                        <summary class="disclosure-summary">
                            <span>What are the two prioritization modes supported by the system?</span>
                        </summary>
                        <div style="padding-top: 10px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                            <strong>Mode 1 (Linear Baseline S_linear):</strong> Computes an equal-weights additive combination of normalized CVSS, EPSS, KEV status, and Asset Criticality.<br>
                            <strong>Mode 2 (Nonlinear Interactive Surface S_nonlinear):</strong> Models multiplicative interactions between intrinsic technical severity, threat likelihood, and asset criticality using a complementary non-additive formulation. In EXP-C1, the top-100 queue overlap between the two modes is only 0.005, confirming severe divergence.
                        </div>
                    </details>

                    <details class="disclosure">
                        <summary class="disclosure-summary">
                            <span>What are Asset Criticality Tiers (x₄)?</span>
                        </summary>
                        <div style="padding-top: 10px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                            Asset Criticality Tiers represent enterprise system importance in 4 controlled synthetic tiers: Tier 1 Low (0.25), Tier 2 Medium (0.50), Tier 3 High (0.75), and Tier 4 Critical Infrastructure (1.00).
                        </div>
                    </details>
                </div>
            </div>
        </div>
    `;
}
