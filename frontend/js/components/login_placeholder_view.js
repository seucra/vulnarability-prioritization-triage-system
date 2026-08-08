/**
 * Authentication Placeholder Component Controller (Phase WDL-1)
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

export function renderLoginPlaceholderView(containerEl) {
    containerEl.innerHTML = `
        <div style="max-width: 540px; margin: 40px auto;">
            <div class="card" style="padding: 32px; border-top: 4px solid var(--primary);">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
                    <div style="background: var(--bg-surface-container); padding: 10px; border-radius: var(--radius-md); color: var(--primary);">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
                    </div>
                    <div>
                        <h3 style="font-size: 18px; font-weight: 700; color: var(--text-main);">Authentication & Role Access</h3>
                        <div style="font-size: 12px; color: var(--text-sub);">Role-Based Access Control (RBAC) Entrypoint</div>
                    </div>
                </div>

                <div style="background: var(--bg-surface-low); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 16px; margin-bottom: 20px; font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                    <strong style="color: var(--primary);">Phase WDL-1 Architecture Notice:</strong>
                    <div style="margin-top: 6px;">
                        The system is currently operating in public demonstration mode. Role-based authentication (Security Analyst, Researcher, and Administrator roles) will be activated in <strong>Phase WDL-2</strong>.
                    </div>
                </div>

                <div style="margin-bottom: 24px;">
                    <div class="input-label" style="margin-bottom: 8px;">Upcoming Functional User Roles:</div>
                    <div style="display: flex; flex-direction: column; gap: 8px; font-size: 12px;">
                        <div style="padding: 10px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                            <strong style="color: var(--primary);">1. Security Analyst:</strong> Search/inspect vulnerabilities, execute predictions, run prioritization simulations, view SHAP attributions.
                        </div>
                        <div style="padding: 10px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                            <strong style="color: var(--tertiary);">2. Researcher:</strong> View research methodology, inspect experiment benchmarks, review dataset provenance, analyze TreeExplainer features.
                        </div>
                        <div style="padding: 10px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                            <strong style="color: var(--success);">3. Administrator:</strong> Monitor system health, review audit logs, manage demonstration user sessions, inspect dataset freeze manifests.
                        </div>
                    </div>
                </div>

                <button class="btn btn-primary" id="btn-login-return-dashboard" style="width: 100%; padding: 10px;">
                    Return to System Dashboard
                </button>
            </div>
        </div>
    `;

    const btnReturn = containerEl.querySelector('#btn-login-return-dashboard');
    if (btnReturn) {
        btnReturn.addEventListener('click', () => {
            window.location.hash = 'dashboard';
        });
    }
}
