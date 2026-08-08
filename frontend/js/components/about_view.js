/**
 * About & Project Research Details Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

export function renderAboutView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">About the Research Project</h2>
                <p class="section-desc">Background, scientific motivation, system purpose, data sources, algorithm formulations, research limitations, and future scope.</p>
            </div>
            <span class="repo-badge" style="font-size: 12px; padding: 6px 12px;">seucra/vulnarability-prioritization-triage-system</span>
        </div>

        <!-- Project Overview & Motivation -->
        <div class="card" style="margin-bottom: 20px;">
            <h3 class="card-title">Project Overview & Scientific Motivation</h3>
            <p style="font-size: 13px; color: var(--text-main); line-height: 1.6; margin-bottom: 12px;">
                This system represents an academic engineering and research effort at the intersection of cybersecurity, machine learning, and quantitative risk modeling.
                The core research reference framework is:
            </p>
            <blockquote style="background: var(--bg-surface-low); border-left: 4px solid var(--primary); padding: 12px 16px; border-radius: var(--radius-md); font-family: var(--font-mono); font-size: 12px; color: var(--text-main); margin-bottom: 12px;">
                "Explainable Risk-Based Vulnerability Prioritization in Hybrid Cloud: Integrating CVSS, EPSS, and CISA KEV with Asset Criticality Signals"
            </blockquote>
            <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                Standard vulnerability management workflows rely heavily on CVSS Base Scores provided by the National Vulnerability Database (NVD). 
                However, CVSS measures intrinsic technical severity rather than real-world exploitation risk or asset context. 
                This project evaluates how combining CVSS severity, EPSS exploitation probability snapshots, CISA Known Exploited Vulnerabilities (KEV) listings, and controlled asset criticality signals can improve triage efficiency.
            </p>
        </div>

        <!-- Data Sources & Provenance -->
        <div class="card" style="margin-bottom: 20px;">
            <h3 class="card-title">Canonical Data Sources</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; font-size: 12px;">
                <div style="background: var(--bg-surface-low); padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                    <strong style="color: var(--primary); font-size: 13px;">NVD CVE Dataset</strong>
                    <div style="margin-top: 6px; color: var(--text-sub);">
                        366,547 canonical vulnerability records covering disclosures from 2002 through 2026. Includes CVSS v2, v3.0, v3.1, and v4.0 scores, CVSS vectors, CWE weakness classifications, and CPE applicability nodes.
                    </div>
                </div>
                <div style="background: var(--bg-surface-low); padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                    <strong style="color: var(--primary); font-size: 13px;">EPSS Score Snapshot</strong>
                    <div style="margin-top: 6px; color: var(--text-sub);">
                        348,900 vulnerability probability records sourced from the Exploit Prediction Scoring System (EPSS). Snapshot dated <strong>2026-07-16T12:03:48Z</strong> (Model version <code>v2026.06.15</code>).
                    </div>
                </div>
                <div style="background: var(--bg-surface-low); padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                    <strong style="color: var(--error); font-size: 13px;">CISA KEV Catalog</strong>
                    <div style="margin-top: 6px; color: var(--text-sub);">
                        1,647 cataloged vulnerabilities confirmed by CISA to be actively exploited in the wild. Includes action deadlines, required remediation steps, and ransomware campaign usage flags.
                    </div>
                </div>
            </div>
        </div>

        <!-- Analytical Models & Formulations -->
        <div class="card" style="margin-bottom: 20px;">
            <h3 class="card-title">Analytical Components & Model Architecture</h3>
            
            <div style="margin-bottom: 16px;">
                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-main); margin-bottom: 6px;">1. Pre-Scoring CVSS v3.1 Estimation (EXP-A1)</h4>
                <p style="font-size: 13px; color: var(--text-sub); line-height: 1.5;">
                    An XGBoost Regressor trained on TF-IDF text features from initial disclosure descriptions and metadata. Estimates CVSS v3.1 base score ($0.0$ to $10.0$) prior to official NVD analyst scoring. Tested benchmark error: $MAE = 0.9750$ points.
                </p>
            </div>

            <div style="margin-bottom: 16px;">
                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-main); margin-bottom: 6px;">2. Publication-Time KEV Risk Prediction (EXP-B2)</h4>
                <p style="font-size: 13px; color: var(--text-sub); line-height: 1.5;">
                    An XGBoost Classifier predicting the probability of future CISA KEV catalog inclusion at publication time under strict feature boundary rules (excluding post-publication EPSS & CVSS scores). Tested benchmark: $PR-AUC = 0.02884$, delivering an $8.96\times$ precision uplift over random baseline ($0.00322$).
                </p>
            </div>

            <div style="margin-bottom: 16px;">
                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-main); margin-bottom: 6px;">3. Controlled Prioritization Surfaces (Mode 1 vs Mode 2)</h4>
                <div style="background: var(--bg-surface-low); padding: 12px; border-radius: var(--radius-md); border: 1px solid var(--border-color); font-family: var(--font-mono); font-size: 12px; color: var(--text-main); line-height: 1.6;">
                    <div><strong>Mode 1 (Linear Equal Weights Baseline):</strong> S_linear = 0.25*x1 + 0.25*x2 + 0.25*x3 + 0.25*x4</div>
                    <div style="margin-top: 4px;"><strong>Mode 2 (Nonlinear Interactive Surface):</strong> S_nonlinear = x4 * [ 1 - (1-x1)^(1+1.0*x3) * (1-x2)^(1+1.5*x3) ]</div>
                </div>
            </div>

            <div>
                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-main); margin-bottom: 6px;">4. Local TreeExplainer SHAP Feature Attribution</h4>
                <p style="font-size: 13px; color: var(--text-sub); line-height: 1.5;">
                    Computes exact Shapley feature attributions for individual predictions, decomposing predictions into positive and negative push factors while explicitly noting causal non-mechanistic disclaimers.
                </p>
            </div>
        </div>

        <!-- Research Limitations & Future Scope -->
        <div class="workspace-grid" style="margin-bottom: 20px;">
            <div class="card">
                <h3 class="card-title" style="color: var(--warning);">Research Limitations</h3>
                <ul style="padding-left: 20px; font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                    <li style="margin-bottom: 6px;"><strong>Static EPSS Snapshot:</strong> EPSS scores represent a single static snapshot (2026-07-16) and were not historical publication-time inputs.</li>
                    <li style="margin-bottom: 6px;"><strong>Publication-Time Features:</strong> Pre-scoring models rely on initial text disclosure quality, which varies across CNAs.</li>
                    <li style="margin-bottom: 6px;"><strong>Controlled Asset Signals:</strong> Asset criticality is evaluated using 4 controlled synthetic tiers ($A \in \{0.25, 0.50, 0.75, 1.00\}$) rather than live enterprise CMDB telemetry.</li>
                </ul>
            </div>

            <div class="card">
                <h3 class="card-title" style="color: var(--primary);">Future Scope</h3>
                <ul style="padding-left: 20px; font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                    <li style="margin-bottom: 6px;">Integration of dynamic historical EPSS time series data to evaluate temporal score velocity.</li>
                    <li style="margin-bottom: 6px;">Ingestion of software dependency graphs (SBOM) for reachability and exploit path analysis.</li>
                    <li style="margin-bottom: 6px;">Exploration of LLM-based semantic extraction for fine-grained attack vector parsing.</li>
                </ul>
            </div>
        </div>
    `;
}
