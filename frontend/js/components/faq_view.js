/**
 * FAQ (Frequently Asked Questions) View Component
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

export function renderFaqView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Frequently Asked Questions (FAQ)</h2>
                <p class="section-desc">Academic background, dataset characterization, machine learning methodology, and application usage.</p>
            </div>
            <span class="badge badge-low" style="font-size: 12px; padding: 6px 12px;">Research Prototype Docs</span>
        </div>

        <div class="faq-container" style="max-width: 900px; display: flex; flex-direction: column; gap: 16px;">

            <!-- System Overview Category -->
            <div class="card" style="margin-bottom: 0;">
                <h3 class="card-title" style="color: var(--primary); margin-bottom: 12px;">1. System Overview & Problem Scope</h3>

                <div class="faq-item" style="margin-bottom: 16px;">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: What is the Vulnerability Prioritization & Triage System?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        This system is a research-backed decision-support web application designed to evaluate machine learning estimation models (CVSS base scores and publication-time KEV risk) and combine them with enterprise asset criticality context for vulnerability triage.
                    </p>
                </div>

                <div class="faq-item" style="margin-bottom: 16px;">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: What core problem in vulnerability management does this research address?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        Organisations face an overwhelming volume of newly disclosed CVEs annually. Official NVD CVSS scoring often experiences disclosure lag (weeks to months), while EPSS scores and CISA KEV listings reflect post-publication observations. This system addresses pre-scoring estimation and publication-time threat risk prediction to enable immediate triage upon disclosure.
                    </p>
                </div>

                <div class="faq-item">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: Is this system intended as a live production cybersecurity platform?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        No. This software is an academic research prototype developed for Web Design Lab evaluation. It operates on a frozen, deterministic research dataset (366,547 CVEs) and static EPSS snapshot (2026-07-16) to ensure experimental reproducibility.
                    </p>
                </div>
            </div>

            <!-- Machine Learning & Methodology Category -->
            <div class="card" style="margin-bottom: 0;">
                <h3 class="card-title" style="color: var(--primary); margin-bottom: 12px;">2. Machine Learning Methodology & Experiments</h3>

                <div class="faq-item" style="margin-bottom: 16px;">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: What is the purpose of Experiment EXP-A1?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        EXP-A1 evaluates pre-scoring CVSS v3.1 base score regression using initial text descriptions and CWE metadata available at publication time. Using an XGBoost regressor, EXP-A1 achieves a Mean Absolute Error (MAE) of 0.9750 on held-out 2025–2026 test disclosures.
                    </p>
                </div>

                <div class="faq-item" style="margin-bottom: 16px;">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: What is Experiment EXP-B2 and why are publication-time feature boundaries strictly enforced?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        EXP-B2 is a publication-time binary classifier predicting whether a newly disclosed vulnerability will eventually enter the CISA KEV catalog. Post-publication signals such as official CVSS scores or EPSS telemetry are strictly excluded during feature extraction to prevent historical data leakage (identified in retrospective experiment EXP-B1). EXP-B2 achieves a Precision-Recall AUC of 0.02884 ($8.96\times$ precision uplift over random baseline).
                    </p>
                </div>

                <div class="faq-item" style="margin-bottom: 16px;">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: What is the temporal evaluation partitioning protocol?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        To prevent temporal data leakage across disclosure years, the dataset is split strictly by publication year:
                        <strong>TRAIN:</strong> 2002–2022 (208,602 CVEs), <strong>VALIDATION:</strong> 2023–2024 (71,061 CVEs for hyperparameter selection), and <strong>TEST:</strong> 2025–2026 (86,884 CVEs held out for final evaluation).
                    </p>
                </div>

                <div class="faq-item">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: How does SHAP explainability work in this system?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        SHAP (SHapley Additive exPlanations) TreeExplainer computes feature contribution values for individual model predictions. Positive SHAP values indicate terms/features increasing severity or KEV probability, while negative values indicate terms reducing risk. SHAP values reflect model decision logic and do not imply physical execution causality.
                    </p>
                </div>
            </div>

            <!-- Prioritization & Asset Context Category -->
            <div class="card" style="margin-bottom: 0;">
                <h3 class="card-title" style="color: var(--primary); margin-bottom: 12px;">3. Prioritization Engine & Asset Context</h3>

                <div class="faq-item" style="margin-bottom: 16px;">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: What are the two prioritization modes supported by the C1 engine?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        <strong>Mode 1 (Linear Baseline $S_{\text{linear}}$):</strong> Computes a linear weighted combination of normalized CVSS, EPSS, KEV status, and Asset Criticality using baseline reference weights.<br>
                        <strong>Mode 2 (Nonlinear Interactive Surface $S_{\text{nonlinear}}$):</strong> Models multiplicative interaction between intrinsic vulnerability severity, threat likelihood, and asset criticality ($S = CVSS_{norm} \times (\alpha \cdot EPSS + \beta \cdot KEV) \times A$).
                    </p>
                </div>

                <div class="faq-item">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: What are Asset Criticality Tiers ($A$)?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        Asset Criticality Tiers represent enterprise system importance in 4 controlled synthetic tiers: Low ($A = 0.25$), Medium ($A = 0.50$), High ($A = 0.75$), and Mission-Critical ($A = 1.00$).
                    </p>
                </div>
            </div>

            <!-- Role Access & Security Category -->
            <div class="card" style="margin-bottom: 0;">
                <h3 class="card-title" style="color: var(--primary); margin-bottom: 12px;">4. Access Control & User Roles</h3>

                <div class="faq-item" style="margin-bottom: 16px;">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: What user roles are supported in the system?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        The system implements 3 explicit roles: <strong>Security Analyst</strong> (operational triage, predictions, prioritization), <strong>Academic Researcher</strong> (methodology, benchmarks, explainability; forbidden from prioritization), and <strong>Administrator</strong> (user directory management and system health monitoring).
                    </p>
                </div>

                <div class="faq-item">
                    <strong style="font-size: 14px; color: var(--text-main); display: block; margin-bottom: 4px;">Q: How are user credentials and sessions secured?</strong>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                        Passwords are hashed using PBKDF2-HMAC-SHA256 with 100,000 iterations and 16-byte random salts. Sessions use HMAC-SHA256 signed bearer tokens with 24-hour expiration. Plaintext passwords are never stored or logged.
                    </p>
                </div>
            </div>

        </div>
    `;
}
