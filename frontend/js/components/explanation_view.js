/**
 * SHAP Explainability Workspace Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderExplanationView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">SHAP Model Explainability</h2>
                <p class="section-desc">Visualizes feature attributions and tree decision boundaries computed using TreeExplainer on frozen EXP-A1 and EXP-B2 models.</p>
            </div>
            <div class="nav-tabs">
                <button class="nav-tab active" id="tab-explain-cvss">EXP-A1 SHAP (CVSS Regressor)</button>
                <button class="nav-tab" id="tab-explain-kev">EXP-B2 SHAP (KEV Classifier)</button>
            </div>
        </div>

        <div class="workspace-grid">
            <!-- Form Card -->
            <div class="card">
                <h3 class="card-title">Vulnerability Input for Explanation</h3>
                <div class="input-group" style="margin-bottom:16px;">
                    <label class="input-label">Description Text</label>
                    <textarea id="explain-desc" class="input-control" rows="4">An unauthenticated remote code execution vulnerability in Apache Log4j2 JNDI feature allows full system takeover.</textarea>
                </div>
                <div class="input-group" style="margin-bottom:16px;">
                    <label class="input-label">Associated CWEs</label>
                    <input type="text" id="explain-cwes" class="input-control" value="CWE-502, CWE-400">
                </div>
                <button class="btn btn-primary" id="btn-run-explain" style="width:100%;">
                    Generate SHAP Explanation
                </button>
            </div>

            <!-- Explanation Output Card -->
            <div class="card">
                <h3 class="card-title">SHAP Feature Contributions</h3>
                <div id="explain-output-container">
                    <div class="empty-state">
                        <p>Enter vulnerability description text and associated CWEs, then click "Generate SHAP Explanation" to compute feature attributions.</p>
                    </div>
                </div>
            </div>
        </div>
    `;

    const tabCvss = containerEl.querySelector('#tab-explain-cvss');
    const tabKev = containerEl.querySelector('#tab-explain-kev');
    const btnRun = containerEl.querySelector('#btn-run-explain');
    const outputContainer = containerEl.querySelector('#explain-output-container');

    let mode = 'cvss'; // 'cvss' | 'kev'

    tabCvss.addEventListener('click', () => {
        mode = 'cvss';
        tabCvss.classList.add('active');
        tabKev.classList.remove('active');
    });

    tabKev.addEventListener('click', () => {
        mode = 'kev';
        tabKev.classList.add('active');
        tabCvss.classList.remove('active');
    });

    btnRun.addEventListener('click', async () => {
        // Check authentication state
        const s = state.getState();
        if (!s.currentUser && !api.getAuthToken()) {
            outputContainer.innerHTML = `
                <div class="empty-state" style="border: 1px dashed var(--primary); background: var(--bg-surface-low); padding: 24px; text-align: center;">
                    <h4 style="margin: 0 0 6px 0; font-size: 15px; color: var(--text-main);">Sign In Required</h4>
                    <p style="margin: 0 0 16px 0; font-size: 13px; color: var(--text-sub);">Please sign in or register a demonstration account to generate SHAP model explanations.</p>
                    <button class="btn btn-primary btn-sm" onclick="window.location.hash='login'">Sign In to Continue</button>
                </div>
            `;
            return;
        }

        const desc = containerEl.querySelector('#explain-desc').value.trim();
        const cwesRaw = containerEl.querySelector('#explain-cwes').value;
        const cweIds = cwesRaw.split(',').map(s => s.trim()).filter(Boolean);

        const payload = {
            description_en: desc,
            cwe_ids: cweIds,
            cpe_count: 5,
            cpe_part_a_count: 5,
            cpe_part_o_count: 0,
            cpe_part_h_count: 0,
            vendor_count: 1,
            product_count: 1,
            pub_month: 12
        };

        outputContainer.innerHTML = `
            <div style="padding:30px; text-align:center;">
                <span class="loading-spinner"></span>
                <p style="margin-top:10px; color:var(--text-sub);">Computing SHAP TreeExplainer values...</p>
            </div>
        `;

        try {
            const res = mode === 'cvss' ? await api.explainCVSS(payload) : await api.explainKEV(payload);
            renderShapResult(outputContainer, res);
        } catch (err) {
            if (err.status === 503 || err.message.includes('503') || err.message.includes('not loaded')) {
                outputContainer.innerHTML = `
                    <div class="empty-state" style="border: 1px dashed var(--warning); background: var(--bg-surface-low); padding: 24px; text-align: center;">
                        <h4 style="margin: 0 0 6px 0; font-size: 15px; color: var(--warning);">Research Model Artifact Unavailable</h4>
                        <p style="margin: 0; font-size: 13px; color: var(--text-sub);">${err.message}</p>
                    </div>
                `;
            } else {
                outputContainer.innerHTML = `
                    <div class="error-banner">
                        <strong>Explanation Error:</strong> ${err.message}
                    </div>
                `;
            }
        }
    });
}

function renderShapResult(containerEl, res) {
    const items = res.top_feature_contributions || [];
    const maxAbs = items.length > 0 ? Math.max(...items.map(i => i.abs_shap_value)) : 1.0;

    const barsHtml = items.map(item => {
        const widthPct = Math.min(100, Math.max(5, (item.abs_shap_value / maxAbs) * 100));
        const isPos = item.shap_value >= 0;
        const barClass = isPos ? 'shap-bar-fill-pos' : 'shap-bar-fill-neg';
        const sign = isPos ? '+' : '';

        return `
            <div class="shap-item">
                <div class="shap-feature-name" title="${item.feature_name}">${item.feature_name}</div>
                <div class="shap-bar-track">
                    <div class="${barClass}" style="width: ${widthPct.toFixed(1)}%;"></div>
                </div>
                <div class="shap-val-text" style="color: ${isPos ? 'var(--error)' : 'var(--success)'}">
                    ${sign}${item.shap_value.toFixed(4)}
                </div>
            </div>
        `;
    }).join('');

    containerEl.innerHTML = `
        <div style="margin-bottom:12px; font-size:12px; color:var(--text-sub);">
            <div><strong>Target Model:</strong> ${res.target_model}</div>
            <div><strong>Expected Base Value:</strong> <span style="font-family:var(--font-mono);">${res.base_value}</span></div>
            <div><strong>Final Prediction Output:</strong> <span style="font-family:var(--font-mono); font-weight:700; color:var(--primary);">${res.predicted_value}</span></div>
        </div>

        <div class="shap-bar-container">
            ${barsHtml}
        </div>
    `;
}
