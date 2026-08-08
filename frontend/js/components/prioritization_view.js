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
                <h2 class="section-title">Controlled Prioritization Sandbox</h2>
                <p class="section-desc">Visualizes differences between the project-controlled linear baseline and nonlinear interactive surface under controlled asset scenarios across Asset Criticality Tiers 1–4.</p>
            </div>
        </div>

        <div class="workspace-grid">
            <!-- Sandbox Controls Form -->
            <div class="card">
                <h3 class="card-title">Scenario Parameters</h3>
                
                <div class="input-group" style="margin-bottom: 16px;">
                    <label class="input-label">CVE Identifier (Optional reference lookup)</label>
                    <input type="text" id="prio-cve-id" class="input-control" value="CVE-2021-44228" placeholder="CVE-2021-44228">
                </div>

                <div class="input-group" style="margin-bottom: 16px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <label class="input-label">Authoritative CVSS Score (x1)</label>
                        <span id="cvss-val-display" style="font-family:var(--font-mono); font-weight:700;">10.0</span>
                    </div>
                    <input type="range" id="prio-cvss-slider" min="0" max="10" step="0.1" value="10.0" style="width:100%;">
                </div>

                <div class="input-group" style="margin-bottom: 16px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <label class="input-label">EPSS Snapshot Score (x2)</label>
                        <span id="epss-val-display" style="font-family:var(--font-mono); font-weight:700;">0.95</span>
                    </div>
                    <input type="range" id="prio-epss-slider" min="0" max="1" step="0.01" value="0.95" style="width:100%;">
                </div>

                <div class="input-group" style="margin-bottom: 20px;">
                    <label class="input-label">CISA KEV Listing Status (x3)</label>
                    <select id="prio-kev-select" class="input-control">
                        <option value="true" selected>Listed in KEV (x3 = 1.0)</option>
                        <option value="false">Not Listed in KEV (x3 = 0.0)</option>
                    </select>
                </div>

                <div class="input-group" style="margin-bottom: 24px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <label class="input-label">Controlled Asset Criticality Tier (x4)</label>
                        <span id="asset-val-display" style="font-family:var(--font-mono); font-weight:700; color:var(--primary);">Tier 3 (High: 0.75)</span>
                    </div>
                    <input type="range" id="prio-asset-slider" min="0.25" max="1.0" step="0.25" value="0.75" style="width:100%;">
                    <div style="display:flex; justify-content:space-between; font-size:10px; color:var(--text-muted); margin-top:2px;">
                        <span>Tier 1 (0.25)</span>
                        <span>Tier 2 (0.50)</span>
                        <span>Tier 3 (0.75)</span>
                        <span>Tier 4 (1.00)</span>
                    </div>
                </div>

                <button class="btn btn-primary" id="btn-calc-priority" style="width:100%;">
                    Calculate Prioritization Comparison
                </button>
            </div>

            <!-- Scoring Results Output -->
            <div class="card">
                <h3 class="card-title">Dual-Mode Scoring Output</h3>
                <div id="prio-output-container">
                    <div class="empty-state">
                        <p>Adjust parameters and click "Calculate Prioritization Comparison" to compare Mode 1 Linear and Mode 2 Nonlinear priority scores.</p>
                    </div>
                </div>
            </div>
        </div>
    `;

    const cvssSlider = containerEl.querySelector('#prio-cvss-slider');
    const epssSlider = containerEl.querySelector('#prio-epss-slider');
    const assetSlider = containerEl.querySelector('#prio-asset-slider');
    const cvssDisp = containerEl.querySelector('#cvss-val-display');
    const epssDisp = containerEl.querySelector('#epss-val-display');
    const assetDisp = containerEl.querySelector('#asset-val-display');

    cvssSlider.addEventListener('input', () => cvssDisp.textContent = parseFloat(cvssSlider.value).toFixed(1));
    epssSlider.addEventListener('input', () => epssDisp.textContent = parseFloat(epssSlider.value).toFixed(2));
    
    assetSlider.addEventListener('input', () => {
        const val = parseFloat(assetSlider.value);
        if (val <= 0.30) assetDisp.textContent = 'Tier 1 (Low: 0.25)';
        else if (val <= 0.60) assetDisp.textContent = 'Tier 2 (Medium: 0.50)';
        else if (val <= 0.85) assetDisp.textContent = 'Tier 3 (High: 0.75)';
        else assetDisp.textContent = 'Tier 4 (Critical: 1.00)';
    });

    const btnCalc = containerEl.querySelector('#btn-calc-priority');
    btnCalc.addEventListener('click', async () => {
        const payload = {
            cve_id: containerEl.querySelector('#prio-cve-id').value.trim() || null,
            cvss_score: parseFloat(cvssSlider.value),
            epss_score: parseFloat(epssSlider.value),
            is_kev: containerEl.querySelector('#prio-kev-select').value === 'true',
            asset_criticality: parseFloat(assetSlider.value),
        };

        const outContainer = containerEl.querySelector('#prio-output-container');
        outContainer.innerHTML = `
            <div style="padding:30px; text-align:center;">
                <span class="loading-spinner"></span>
                <p style="margin-top:10px; color:var(--text-sub);">Computing Mode 1 & Mode 2 prioritization scores...</p>
            </div>
        `;

        try {
            const res = await api.prioritize(payload);
            renderPrioritizationResult(outContainer, res);
        } catch (err) {
            outContainer.innerHTML = `
                <div class="error-banner">
                    <strong>Error calculating priority:</strong> ${err.message}
                </div>
            `;
        }
    });

    // Auto calculate initial scenario
    btnCalc.click();
}

function renderPrioritizationResult(containerEl, res) {
    const lin = res.linear_baseline_mode_1;
    const nonlin = res.nonlinear_surface_mode_2;
    const delta = nonlin.priority_score - lin.priority_score;

    containerEl.innerHTML = `
        <div class="scoring-comparison-grid">
            <!-- Mode 1 Linear Card -->
            <div class="scoring-card">
                <div class="input-label" style="font-size:11px;">MODE 1 — Transparent Linear Baseline</div>
                <div class="score-display">${lin.priority_score.toFixed(4)}</div>
                <div style="font-size:11px; color:var(--text-sub); margin-top:6px;">
                    Formulation: S_linear = 0.25*x1 + 0.25*x2 + 0.25*x3 + 0.25*x4
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:4px; font-style:italic;">
                    Project-controlled equal weights baseline
                </div>
            </div>

            <!-- Mode 2 Nonlinear Card -->
            <div class="scoring-card" style="border-color: var(--primary);">
                <div class="input-label" style="font-size:11px; color:var(--primary);">MODE 2 — Nonlinear Interactive Surface</div>
                <div class="score-display" style="color:var(--primary);">${nonlin.priority_score.toFixed(4)}</div>
                <div style="font-size:11px; color:var(--text-sub); margin-top:6px;">
                    Formulation: S_nonlinear = x4 * [ 1 - (1-x1)^(1+1.0*x3) * (1-x2)^(1+1.5*x3) ]
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:4px; font-style:italic;">
                    Multiplicative non-additive surface (alpha=1.0, beta=1.5)
                </div>
            </div>
        </div>

        <div style="background-color: var(--bg-surface-low); border: 1px solid var(--border-color); padding: 14px; border-radius: var(--radius-md); margin-top: 16px; font-size: 12px;">
            <div style="display:flex; justify-width:space-between; align-items:center; margin-bottom:6px;">
                <strong>Score Shift (Mode 2 vs Mode 1):</strong>
                <span style="font-family:var(--font-mono); font-weight:700; color: ${delta >= 0 ? 'var(--primary)' : 'var(--error)'}">
                    ${delta >= 0 ? '+' : ''}${delta.toFixed(4)} points
                </span>
            </div>
            <div style="color: var(--text-sub); line-height: 1.5;">
                ${res.methodology_note}
            </div>
        </div>
    `;
}
