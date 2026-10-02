/**
 * About & Project Research Details Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

export function renderAboutView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">About the Research Project</h2>
                <p class="section-desc">Academic background, scientific motivation, system purpose, canonical data sources, analytical formulations, and research boundaries.</p>
            </div>
            <span class="badge badge-gold" style="font-size: 11px;">seucra/vulnarability-prioritization-triage-system</span>
        </div>

        <div style="max-width: 960px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px;">
            <!-- Project Overview & Motivation -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" style="font-size: 16px; margin: 0;">Scientific Motivation</h3>
                </div>
                <p style="font-size: 13px; color: var(--text-primary); line-height: 1.6; margin-bottom: 14px;">
                    Standard vulnerability remediation workflows rely heavily on CVSS Base Scores published by the National Vulnerability Database (NVD). 
                    However, CVSS measures intrinsic technical severity in a vacuum rather than real-world threat probability or local asset context. 
                    Furthermore, official NVD CVSS scoring frequently suffers from multi-week disclosure lags, while EPSS scores and CISA KEV listings reflect post-publication observations.
                </p>
                <div style="background: var(--bg-muted); border-left: 3px solid var(--accent-gold); padding: 12px 16px; border-radius: var(--radius-sm); font-size: 13px; color: var(--text-primary); line-height: 1.5; margin-bottom: 14px;">
                    <strong>Research Objective:</strong> Evaluate pre-scoring estimation and publication-time exploitation prediction models under strict temporal isolation, and examine the divergence between additive linear scoring and interactive nonlinear risk surfaces across enterprise asset tiers.
                </div>
            </div>

            <!-- Canonical Data Sources -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" style="font-size: 16px; margin: 0;">Canonical Data Sources (Frozen 2026-07-26)</h3>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px;">
                    <div style="background: var(--bg-muted); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <strong style="color: var(--text-primary); font-size: 13px;">NVD CVE Corpus</strong>
                        <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--text-primary); margin: 4px 0 6px 0;">366,547 Records</div>
                        <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">
                            Disclosures spanning 2002 through 2026. Contains CVSS v2/v3.x/v4.0 metrics, CWE weakness mappings, and CPE software stack applicability nodes.
                        </div>
                    </div>
                    <div style="background: var(--bg-muted); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <strong style="color: var(--text-primary); font-size: 13px;">FIRST EPSS Scores</strong>
                        <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--text-primary); margin: 4px 0 6px 0;">348,900 Records</div>
                        <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">
                            Static snapshot dated <strong>2026-07-16T12:03:48Z</strong> (Model version <code>v2026.06.15</code>). Subjected to retrospective leakage audits.
                        </div>
                    </div>
                    <div style="background: var(--bg-muted); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <strong style="color: var(--accent-scarlet); font-size: 13px;">CISA KEV Catalog</strong>
                        <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--accent-scarlet); margin: 4px 0 6px 0;">1,647 Records</div>
                        <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">
                            Authoritative catalog of vulnerabilities confirmed to be actively weaponized in the wild, including federal remediation deadlines.
                        </div>
                    </div>
                </div>
            </div>

            <!-- Analytical Components & Formulations -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" style="font-size: 16px; margin: 0;">Analytical Models & Formulations</h3>
                </div>
                
                <div style="display: flex; flex-direction: column; gap: 14px;">
                    <div>
                        <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">1. Pre-Scoring CVSS v3.1 Estimation (EXP-A1)</div>
                        <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.5; margin: 0;">
                            XGBoost Regressor evaluated on held-out 2025–2026 test disclosures. Achieves test benchmark MAE = 0.9750 points (vs Ridge baseline: 1.0954, +11.0% relative improvement).
                        </p>
                    </div>

                    <div>
                        <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">2. Publication-Time KEV Risk Prediction (EXP-B2)</div>
                        <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.5; margin: 0;">
                            XGBoost Classifier predicting future CISA KEV catalog inclusion under strict publication-time isolation (excluding post-publication EPSS and CVSS). Tested benchmark PR-AUC = 0.02884 (~5.5× uplift over random baseline).
                        </p>
                    </div>

                    <div>
                        <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">3. Controlled Prioritization Surfaces (Mode 1 vs Mode 2)</div>
                        <div style="background: var(--bg-muted); padding: 12px 14px; border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 11px; color: var(--text-primary); line-height: 1.6; margin-top: 4px;">
                            <div>Mode 1 (Linear Baseline): S_linear = 0.25·(x₁/10) + 0.25·x₂ + 0.25·x₃ + 0.25·x₄</div>
                            <div style="margin-top: 4px;">Mode 2 (Nonlinear Surface): S_nonlinear = x₄ · [ 1 - (1 - x₁/10)^(1+α·x₃) · (1 - x₂)^(1+β·x₃) ]</div>
                        </div>
                    </div>

                    <div>
                        <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">4. Local TreeExplainer SHAP Feature Attribution</div>
                        <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.5; margin: 0;">
                            Decomposes individual tree decisions into directional push factors. Accompanied by causal caveats clarifying that attributions reflect statistical training correlations.
                        </p>
                    </div>
                </div>
            </div>

            <!-- Research Limitations & Future Scope -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 18px;">
                <div class="card" style="margin-bottom: 0;">
                    <div class="card-header" style="padding-bottom: 12px; margin-bottom: 14px; border-bottom: 1px solid var(--border-subtle);">
                        <h4 style="font-size: 14px; font-weight: 600; color: var(--accent-scarlet); margin: 0;">Research Limitations</h4>
                    </div>
                    <ul style="padding-left: 18px; margin: 0; font-size: 12px; color: var(--text-secondary); line-height: 1.6;">
                        <li><strong>Static Snapshot:</strong> EPSS scores represent a static snapshot (2026-07-16) and were not historical publication-time inputs.</li>
                        <li><strong>Text Quality:</strong> Pre-scoring models depend on initial text disclosure completeness, which varies across CNAs.</li>
                        <li><strong>Controlled Tiers:</strong> Asset criticality is evaluated using 4 controlled synthetic tiers ($A \in \{0.25, 0.50, 0.75, 1.00\}$) rather than dynamic CMDB feeds.</li>
                    </ul>
                </div>

                <div class="card" style="margin-bottom: 0;">
                    <div class="card-header" style="padding-bottom: 12px; margin-bottom: 14px; border-bottom: 1px solid var(--border-subtle);">
                        <h4 style="font-size: 14px; font-weight: 600; color: var(--accent-gold); margin: 0;">Future Research Scope</h4>
                    </div>
                    <ul style="padding-left: 18px; margin: 0; font-size: 12px; color: var(--text-secondary); line-height: 1.6;">
                        <li>Integration of dynamic historical EPSS time series data to evaluate temporal score velocity.</li>
                        <li>Ingestion of software dependency graphs (SBOM) for reachability and exploit path analysis.</li>
                        <li>Evaluation of transformer embeddings for fine-grained attack vector parsing.</li>
                    </ul>
                </div>
            </div>
        </div>
    `;
}
