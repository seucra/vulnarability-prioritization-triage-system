/**
 * Prioritization Workspace Component Controller (Mode 1 Linear vs Mode 2 Nonlinear)
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderPrioritizationView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Prioritization Sandbox</h2>
                <p class="section-desc">Evaluates differences between the project-controlled linear baseline and nonlinear interactive risk surface across asset criticality scenarios (Tiers 1–4).</p>
            </div>
        </div>

        <div class="workspace-grid" style="grid-template-columns: 1.05fr 0.95fr; gap: 24px; align-items: start;">
            <!-- Sandbox Controls Form -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 18px; border-bottom: 1px solid var(--border-subtle);">
                    <div style="display: flex; justify-content: space-between; align-items: baseline; width: 100%;">
                        <h3 class="card-title" style="font-size: 15px;">Scenario Parameters</h3>
                        <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">TUPLE [x₁, x₂, x₃, x₄]</span>
                    </div>
                </div>

                <!-- Reference CVE Lookup -->
                <div class="form-group" style="margin-bottom: 16px;">
                    <label class="form-label" for="prio-cve-id">Reference CVE Identifier (Optional Lookup)</label>
                    <div style="display: flex; gap: 8px;">
                        <input type="text" id="prio-cve-id" class="form-input" value="CVE-2021-44228" placeholder="e.g. CVE-2021-44228" style="font-family: var(--font-mono); text-transform: uppercase;">
                        <button type="button" class="btn btn-secondary btn-sm" id="btn-fetch-cve" style="white-space: nowrap;">
                            Fetch Metrics
                        </button>
                    </div>
                    <span class="form-hint">Load authoritative CVSS, EPSS snapshot, and KEV listing directly from database.</span>
                </div>

                <div style="border-top: 1px solid var(--border-subtle); padding-top: 16px; margin-bottom: 16px;">
                    <!-- CVSS Slider -->
                    <div class="form-group" style="margin-bottom: 16px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <label class="form-label" for="prio-cvss-slider" style="margin-bottom: 0;">Authoritative CVSS v3.1 (x₁)</label>
                            <span id="cvss-val-display" style="font-family: var(--font-mono); font-size: 13px; font-weight: 600; color: var(--text-primary);">10.0</span>
                        </div>
                        <input type="range" id="prio-cvss-slider" class="range-slider" min="0" max="10" step="0.1" value="10.0" style="width: 100%;">
                        <div style="display: flex; justify-content: space-between; font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;">
                            <span>0.0</span>
                            <span>5.0</span>
                            <span>10.0</span>
                        </div>
                    </div>

                    <!-- EPSS Slider -->
                    <div class="form-group" style="margin-bottom: 16px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <label class="form-label" for="prio-epss-slider" style="margin-bottom: 0;">EPSS Snapshot Score (x₂)</label>
                            <span id="epss-val-display" style="font-family: var(--font-mono); font-size: 13px; font-weight: 600; color: var(--text-primary);">0.95</span>
                        </div>
                        <input type="range" id="prio-epss-slider" class="range-slider" min="0" max="1" step="0.01" value="0.95" style="width: 100%;">
                        <div style="display: flex; justify-content: space-between; font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;">
                            <span>0.00</span>
                            <span>0.50</span>
                            <span>1.00</span>
                        </div>
                    </div>

                    <!-- CISA KEV Selector -->
                    <div class="form-group" style="margin-bottom: 16px;">
                        <label class="form-label" for="prio-kev-select">CISA KEV Listing Status (x₃)</label>
                        <select id="prio-kev-select" class="form-select">
                            <option value="true" selected>Listed in KEV catalog (x₃ = 1.0)</option>
                            <option value="false">Not listed in KEV (x₃ = 0.0)</option>
                        </select>
                    </div>

                    <!-- Asset Criticality Slider -->
                    <div class="form-group" style="margin-bottom: 22px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <label class="form-label" for="prio-asset-slider" style="margin-bottom: 0;">Asset Criticality Tier (x₄)</label>
                            <span id="asset-val-display" style="font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--accent-scarlet);">Tier 3 · High (0.75)</span>
                        </div>
                        <input type="range" id="prio-asset-slider" class="range-slider" min="0.25" max="1.0" step="0.25" value="0.75" style="width: 100%;">
                        <div style="display: flex; justify-content: space-between; font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;">
                            <span>T1 (0.25)</span>
                            <span>T2 (0.50)</span>
                            <span>T3 (0.75)</span>
                            <span>T4 (1.00)</span>
                        </div>
                    </div>
                </div>

                <button class="btn btn-primary" id="btn-calc-priority" type="button" style="width: 100%; justify-content: center; height: 38px;">
                    Calculate Prioritization Comparison
                </button>
            </div>

            <!-- Scoring Results Output -->
            <div>
                <div class="card" id="prioritization-result-card" style="margin-bottom: 20px;">
                    <div class="card-header" style="padding-bottom: 12px; margin-bottom: 18px; border-bottom: 1px solid var(--border-subtle);">
                        <h3 class="card-title" style="font-size: 15px;">Dual-Mode Scoring Evaluation</h3>
                    </div>
                    <div id="prio-output-container">
                        <div class="empty-state" style="padding: 48px 24px;">
                            <div style="font-family: var(--font-mono); font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">AWAITING EVALUATION</div>
                            <p style="margin: 0; font-size: 13px; color: var(--text-secondary); max-width: 320px; margin-left: auto; margin-right: auto;">
                                Adjust scenario parameter sliders or lookup a reference CVE, then compute dual-mode comparative priority scores.
                            </p>
                        </div>
                    </div>
                </div>

                <!-- Mathematical Formulation & Saturation Disclosure -->
                <details class="disclosure">
                    <summary class="disclosure-summary">
                        <span>Mathematical Formulations & CVSS 10.0 Saturation Analysis</span>
                    </summary>
                    <div style="padding-top: 14px; font-size: 12px; color: var(--text-secondary); line-height: 1.6;">
                        <div style="margin-bottom: 12px;">
                            <strong style="color: var(--text-primary); font-family: var(--font-mono); font-size: 11px;">MODE 1 · LINEAR EQUAL-WEIGHTS BASELINE:</strong>
                            <div style="background: var(--bg-muted); padding: 8px 12px; border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 11px; margin-top: 4px; color: var(--text-primary);">
                                S_linear = 0.25 · (x₁/10) + 0.25 · x₂ + 0.25 · x₃ + 0.25 · x₄
                            </div>
                        </div>

                        <div style="margin-bottom: 12px;">
                            <strong style="color: var(--text-primary); font-family: var(--font-mono); font-size: 11px;">MODE 2 · NONLINEAR MULTIPLICATIVE SURFACE:</strong>
                            <div style="background: var(--bg-muted); padding: 8px 12px; border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 11px; margin-top: 4px; color: var(--text-primary);">
                                S_nonlinear = x₄ · [ 1 - (1 - x₁/10)^(1 + α·x₃) · (1 - x₂)^(1 + β·x₃) ]
                            </div>
                            <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">
                                Default empirical parameters: α = 1.0, β = 1.5.
                            </div>
                        </div>

                        <div style="border-top: 1px solid var(--border-subtle); padding-top: 10px; margin-top: 10px;">
                            <strong style="color: var(--text-primary);">CVSS 10.0 Saturation Analysis:</strong>
                            In linear additive scoring (Mode 1), a maximum CVSS score of 10.0 saturates severity contribution equally regardless of whether real-world exploitation is verified. Consequently, dormant vulnerabilities without active exploitation consume equal priority. Mode 2 replaces additive summation with a complementary multiplicative risk surface: confirmed KEV exploitation (x₃ = 1) exponentially compounds the interaction between severity and exploit likelihood, separating weaponized threats from unexploited vulnerabilities without ceiling saturation.
                        </div>
                    </div>
                </details>
            </div>
        </div>
    `;

    const cvssSlider = containerEl.querySelector('#prio-cvss-slider');
    const epssSlider = containerEl.querySelector('#prio-epss-slider');
    const assetSlider = containerEl.querySelector('#prio-asset-slider');
    const kevSelect = containerEl.querySelector('#prio-kev-select');
    const cvssDisp = containerEl.querySelector('#cvss-val-display');
    const epssDisp = containerEl.querySelector('#epss-val-display');
    const assetDisp = containerEl.querySelector('#asset-val-display');
    const cveInput = containerEl.querySelector('#prio-cve-id');
    const btnFetch = containerEl.querySelector('#btn-fetch-cve');
    const btnCalc = containerEl.querySelector('#btn-calc-priority');

    cvssSlider.addEventListener('input', () => {
        cvssDisp.textContent = parseFloat(cvssSlider.value).toFixed(1);
    });

    epssSlider.addEventListener('input', () => {
        epssDisp.textContent = parseFloat(epssSlider.value).toFixed(2);
    });
    
    assetSlider.addEventListener('input', () => {
        const val = parseFloat(assetSlider.value);
        if (val <= 0.30) assetDisp.textContent = 'Tier 1 · Low (0.25)';
        else if (val <= 0.60) assetDisp.textContent = 'Tier 2 · Medium (0.50)';
        else if (val <= 0.85) assetDisp.textContent = 'Tier 3 · High (0.75)';
        else assetDisp.textContent = 'Tier 4 · Critical (1.00)';
    });

    // Optional CVE metric prefill
    btnFetch.addEventListener('click', async () => {
        const cveId = cveInput.value.trim().toUpperCase();
        if (!cveId) return;

        btnFetch.disabled = true;
        btnFetch.textContent = 'Fetching...';

        try {
            const vuln = await api.getVulnerability(cveId);
            if (vuln.cvss_v31_base_score !== null && vuln.cvss_v31_base_score !== undefined) {
                cvssSlider.value = vuln.cvss_v31_base_score;
                cvssDisp.textContent = vuln.cvss_v31_base_score.toFixed(1);
            }
            if (vuln.epss_score !== null && vuln.epss_score !== undefined) {
                epssSlider.value = vuln.epss_score;
                epssDisp.textContent = vuln.epss_score.toFixed(2);
            }
            if (vuln.is_kev !== null && vuln.is_kev !== undefined) {
                kevSelect.value = vuln.is_kev ? 'true' : 'false';
            }
        } catch (err) {
            alert(`Could not load metrics for ${cveId}: ${err.message}`);
        } finally {
            btnFetch.disabled = false;
            btnFetch.textContent = 'Fetch Metrics';
        }
    });

    btnCalc.addEventListener('click', async () => {
        const outContainer = containerEl.querySelector('#prio-output-container');

        if (!state.isAuthenticated()) {
            outContainer.innerHTML = `
                <div style="background: var(--bg-muted); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 24px; text-align: center;">
                    <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--accent-scarlet); margin-bottom: 6px;">AUTHENTICATION REQUIRED</div>
                    <p style="margin: 0 0 16px 0; font-size: 13px; color: var(--text-secondary);">
                        Please sign in with a registered analyst or researcher demonstration account to compute prioritization scores.
                    </p>
                    <button class="btn btn-primary btn-sm" type="button" onclick="window.location.hash='login'">Sign In to Continue</button>
                </div>
            `;
            return;
        }

        const payload = {
            cve_id: cveInput.value.trim().toUpperCase() || null,
            cvss_score: parseFloat(cvssSlider.value),
            epss_score: parseFloat(epssSlider.value),
            is_kev: kevSelect.value === 'true',
            asset_criticality: parseFloat(assetSlider.value),
        };

        outContainer.innerHTML = `
            <div style="padding: 48px 24px; text-align: center;">
                <span class="loading-spinner"></span>
                <p style="margin-top: 14px; font-size: 13px; color: var(--text-secondary);">Computing Mode 1 and Mode 2 priority scores...</p>
            </div>
        `;

        try {
            const res = await api.prioritize(payload);
            renderPrioritizationResult(outContainer, res);
        } catch (err) {
            outContainer.innerHTML = `
                <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 16px;">
                    <div style="font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--accent-scarlet);">EVALUATION ERROR</div>
                    <div style="margin-top: 6px; font-size: 13px; color: var(--text-primary); line-height: 1.5;">${escapeHtml(err.message)}</div>
                </div>
            `;
        }
    });
}

function renderPrioritizationResult(containerEl, res) {
    const lin = res.linear_baseline_mode_1;
    const nonlin = res.nonlinear_surface_mode_2;
    const delta = nonlin.priority_score - lin.priority_score;
    const isPositiveShift = delta >= 0;

    containerEl.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
            <!-- Mode 1 Linear Card -->
            <div style="background: var(--bg-muted); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 16px;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin-bottom: 4px;">
                    MODE 1 · LINEAR
                </div>
                <div style="font-family: var(--font-mono); font-size: 36px; font-weight: 700; color: var(--text-primary); line-height: 1.1;">
                    ${lin.priority_score.toFixed(4)}
                </div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px;">
                    Equal-weights additive baseline
                </div>
            </div>

            <!-- Mode 2 Nonlinear Card -->
            <div style="background: var(--bg-surface); border: 1px solid var(--border-strong); border-top: 3px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 16px;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--accent-scarlet); margin-bottom: 4px;">
                    MODE 2 · NONLINEAR
                </div>
                <div style="font-family: var(--font-mono); font-size: 36px; font-weight: 700; color: var(--text-primary); line-height: 1.1;">
                    ${nonlin.priority_score.toFixed(4)}
                </div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px;">
                    Multiplicative interactive surface
                </div>
            </div>
        </div>

        <div style="border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); overflow: hidden; margin-bottom: 14px;">
            <div style="padding: 10px 14px; background: var(--bg-muted); display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 12px; font-weight: 500; color: var(--text-secondary);">Score Divergence (Δ Mode 2 − Mode 1)</span>
                <span style="font-family: var(--font-mono); font-size: 14px; font-weight: 700; color: ${isPositiveShift ? 'var(--accent-scarlet)' : 'var(--text-secondary)'};">
                    ${isPositiveShift ? '+' : ''}${delta.toFixed(4)} pts
                </span>
            </div>
        </div>

        <div style="font-size: 11px; color: var(--text-muted); line-height: 1.5; border-left: 2px solid var(--border-strong); padding-left: 10px;">
            ${escapeHtml(res.methodology_note || 'Mode 2 dynamically weights joint CVSS and EPSS interactions under verified KEV exploitation.')}
        </div>
    `;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
