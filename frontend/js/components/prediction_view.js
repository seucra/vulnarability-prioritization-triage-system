/**
 * Predictive Analysis Workspace Component Controller (EXP-A1 & EXP-B2)
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderPredictionView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Predictive Machine Learning Workspace</h2>
                <p class="section-desc">Run frozen pre-scoring CVSS v3.1 estimation (EXP-A1) and publication-time CISA KEV risk prediction (EXP-B2).</p>
            </div>
            <div class="nav-tabs">
                <button class="nav-tab active" id="tab-pred-cvss">EXP-A1 CVSS Estimation</button>
                <button class="nav-tab" id="tab-pred-kev">EXP-B2 KEV Risk Prediction</button>
            </div>
        </div>

        <div class="workspace-grid">
            <!-- Form Card -->
            <div class="card">
                <h3 class="card-title" id="pred-form-title">EXP-A1 Pre-Scoring CVSS Estimation</h3>
                
                <div class="input-group" style="margin-bottom: 16px;">
                    <label class="input-label">Vulnerability Description Text</label>
                    <textarea id="pred-description" class="input-control" rows="4" placeholder="Enter vulnerability disclosure description text (minimum 10 characters)...">An unauthenticated remote code execution vulnerability in Apache Log4j2 JNDI feature allows full system takeover.</textarea>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
                    <div class="input-group">
                        <label class="input-label">CWE Weaknesses (Comma Separated)</label>
                        <input type="text" id="pred-cwes" class="input-control" value="CWE-502, CWE-400">
                    </div>
                    <div class="input-group">
                        <label class="input-label">Publication Month (1-12)</label>
                        <input type="number" id="pred-month" class="input-control" min="1" max="12" value="12">
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 16px;">
                    <div class="input-group">
                        <label class="input-label">CPE Count</label>
                        <input type="number" id="pred-cpe-count" class="input-control" min="0" value="5">
                    </div>
                    <div class="input-group">
                        <label class="input-label">App CPEs (Part A)</label>
                        <input type="number" id="pred-cpe-a" class="input-control" min="0" value="5">
                    </div>
                    <div class="input-group">
                        <label class="input-label">OS CPEs (Part O)</label>
                        <input type="number" id="pred-cpe-o" class="input-control" min="0" value="0">
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px;">
                    <div class="input-group">
                        <label class="input-label">Vendor Count</label>
                        <input type="number" id="pred-vendor-count" class="input-control" min="0" value="1">
                    </div>
                    <div class="input-group">
                        <label class="input-label">Product Count</label>
                        <input type="number" id="pred-product-count" class="input-control" min="0" value="1">
                    </div>
                </div>

                <!-- Boundary Prohibited Features Toggle for B2 Testing -->
                <div id="b2-boundary-warning-box" style="display: none; background: #fffbe6; border: 1px solid #ffe58f; padding: 12px; border-radius: var(--radius-md); margin-bottom: 16px; font-size: 12px; color: #873800;">
                    <strong>Publication-Time Feature Boundary Rule:</strong> Post-publication features (EPSS snapshot scores & CVSS vectors) are strictly prohibited for EXP-B2. Submitting post-publication features will trigger an HTTP 422 validation error from the backend.
                </div>

                <button class="btn btn-primary" id="btn-run-prediction" style="width: 100%;">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                    Run Model Prediction
                </button>
            </div>

            <!-- Results Card -->
            <div>
                <div class="card" id="prediction-result-card">
                    <h3 class="card-title">Model Prediction Result</h3>
                    <div id="prediction-output-body">
                        <div class="empty-state">
                            <p>Fill in vulnerability metadata and click "Run Model Prediction" to evaluate frozen Phase 3 inference models.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    const tabCvss = containerEl.querySelector('#tab-pred-cvss');
    const tabKev = containerEl.querySelector('#tab-pred-kev');
    const formTitle = containerEl.querySelector('#pred-form-title');
    const boundaryBox = containerEl.querySelector('#b2-boundary-warning-box');
    const btnRun = containerEl.querySelector('#btn-run-prediction');

    let currentMode = 'cvss'; // 'cvss' | 'kev'

    tabCvss.addEventListener('click', () => {
        currentMode = 'cvss';
        tabCvss.classList.add('active');
        tabKev.classList.remove('active');
        formTitle.textContent = 'EXP-A1 Pre-Scoring CVSS Estimation';
        boundaryBox.style.display = 'none';
    });

    tabKev.addEventListener('click', () => {
        currentMode = 'kev';
        tabKev.classList.add('active');
        tabCvss.classList.remove('active');
        formTitle.textContent = 'EXP-B2 Publication-Time KEV Risk Prediction';
        boundaryBox.style.display = 'block';
    });

    btnRun.addEventListener('click', async () => {
        const desc = containerEl.querySelector('#pred-description').value.trim();
        if (desc.length < 10) {
            alert('Vulnerability description must be at least 10 characters.');
            return;
        }

        const cwesRaw = containerEl.querySelector('#pred-cwes').value;
        const cweIds = cwesRaw.split(',').map(s => s.trim()).filter(Boolean);
        
        const payload = {
            description_en: desc,
            cwe_ids: cweIds,
            pub_month: parseInt(containerEl.querySelector('#pred-month').value) || 1,
            cpe_count: parseInt(containerEl.querySelector('#pred-cpe-count').value) || 0,
            cpe_part_a_count: parseInt(containerEl.querySelector('#pred-cpe-a').value) || 0,
            cpe_part_o_count: parseInt(containerEl.querySelector('#pred-cpe-o').value) || 0,
            cpe_part_h_count: 0,
            vendor_count: parseInt(containerEl.querySelector('#pred-vendor-count').value) || 0,
            product_count: parseInt(containerEl.querySelector('#pred-product-count').value) || 0,
        };

        const outputBody = containerEl.querySelector('#prediction-output-body');
        outputBody.innerHTML = `
            <div style="padding: 30px; text-align: center;">
                <span class="loading-spinner"></span>
                <p style="margin-top: 10px; color: var(--text-sub);">Running frozen ${currentMode.toUpperCase()} inference model...</p>
            </div>
        `;

        try {
            if (currentMode === 'cvss') {
                const res = await api.predictCVSS(payload);
                renderCvssResult(outputBody, res);
            } else {
                const res = await api.predictKEV(payload);
                renderKevResult(outputBody, res);
            }
        } catch (err) {
            outputBody.innerHTML = `
                <div class="error-banner" style="flex-direction: column; align-items: flex-start;">
                    <strong>Model Prediction Error (HTTP ${err.status || 500}):</strong>
                    <div style="margin-top: 4px; font-family: var(--font-mono); font-size: 12px;">${escapeHtml(err.message)}</div>
                </div>
            `;
        }
    });
}

function renderCvssResult(containerEl, res) {
    containerEl.innerHTML = `
        <div style="margin-bottom: 16px;">
            <div class="input-label">${res.prediction_label}</div>
            <div style="font-family: var(--font-mono); font-size: 40px; font-weight: 700; color: var(--primary);">
                ${res.predicted_cvss_v31_base_score.toFixed(2)}
            </div>
        </div>

        <div style="background-color: var(--bg-surface-low); border: 1px solid var(--border-color); padding: 12px; border-radius: var(--radius-md); font-size: 12px; margin-bottom: 16px;">
            <div><strong>Model Architecture:</strong> ${res.model_name}</div>
            <div><strong>Phase 3 Research Benchmark MAE:</strong> ${res.mae_test_benchmark} points</div>
            ${res.authoritative_cvss_v31_base_score ? `<div style="color:var(--primary); font-weight:600; margin-top:4px;">Authoritative NVD Score: ${res.authoritative_cvss_v31_base_score}</div>` : ''}
        </div>

        <div style="font-size: 11px; color: var(--text-sub); line-height: 1.5; font-style: italic;">
            ${res.disclaimer}
        </div>
    `;
}

function renderKevResult(containerEl, res) {
    let riskBadge = 'badge-low';
    if (res.risk_classification === 'HIGH_RISK') riskBadge = 'badge-critical';
    else if (res.risk_classification === 'ELEVATED_RISK') riskBadge = 'badge-high';

    containerEl.innerHTML = `
        <div style="margin-bottom: 16px;">
            <div class="input-label">Predicted Future KEV Catalog Inclusion Probability</div>
            <div style="display: flex; align-items: center; gap: 12px; margin-top: 4px;">
                <div style="font-family: var(--font-mono); font-size: 36px; font-weight: 700; color: var(--primary);">
                    ${(res.predicted_kev_probability * 100).toFixed(2)}%
                </div>
                <span class="badge ${riskBadge}">${res.risk_classification}</span>
            </div>
        </div>

        <div style="background-color: var(--bg-surface-low); border: 1px solid var(--border-color); padding: 12px; border-radius: var(--radius-md); font-size: 12px; margin-bottom: 16px;">
            <div><strong>Prediction Boundary Point:</strong> ${res.prediction_point}</div>
            <div><strong>Model Architecture:</strong> ${res.model_name}</div>
            <div><strong>Phase 3 Research Benchmark PR-AUC:</strong> ${res.pr_auc_test_benchmark}</div>
            <div><strong>Uplift vs Random:</strong> ${res.uplift_vs_random}</div>
        </div>

        <div style="font-size: 11px; color: var(--text-sub); line-height: 1.5; font-style: italic;">
            Target Definition: ${res.target_definition}. EPSS scores and CVSS vectors are strictly excluded at publication time.
        </div>
    `;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
