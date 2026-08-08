/**
 * User Profile Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderProfileView(containerEl) {
    const s = state.getState();
    const user = s.currentUser;

    if (!user) {
        containerEl.innerHTML = `
            <div style="max-width: 500px; margin: 40px auto; text-align: center;">
                <div class="card">
                    <h3 style="font-size: 18px; margin-bottom: 12px; color: var(--error);">Session Unauthenticated</h3>
                    <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 20px;">You are not currently signed into an active session.</p>
                    <button class="btn btn-primary" onclick="window.location.hash='login'">Sign In</button>
                </div>
            </div>
        `;
        return;
    }

    const roleBadgeClass = user.role === 'admin' ? 'badge-high' : user.role === 'analyst' ? 'badge-low' : 'badge-medium';
    const roleTitle = user.role === 'admin' ? 'Administrator' : user.role === 'analyst' ? 'Security Analyst' : 'Academic Researcher';

    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">User Account Profile</h2>
                <p class="section-desc">Authenticated session details, role permissions, and session management.</p>
            </div>
            <button class="btn btn-outline btn-sm" id="btn-profile-logout" style="color: var(--error); border-color: var(--error);">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                Sign Out / End Session
            </button>
        </div>

        <div class="workspace-grid">
            <!-- User Identity Card -->
            <div class="card">
                <div style="display: flex; align-items: center; gap: 16px; margin-bottom: 20px;">
                    <div style="background: var(--primary-container); color: var(--on-primary-container); width: 56px; height: 56px; border-radius: var(--radius-full); display: flex; align-items: center; justify-content: center; font-size: 22px; font-weight: 700;">
                        ${user.name.charAt(0).toUpperCase()}
                    </div>
                    <div>
                        <h3 style="font-size: 20px; font-weight: 700; color: var(--text-main);">${user.name}</h3>
                        <div style="font-size: 13px; color: var(--text-sub);">${user.email}</div>
                        <div style="margin-top: 6px;">
                            <span class="badge ${roleBadgeClass}">${roleTitle}</span>
                        </div>
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 12px;">
                    <div style="background: var(--bg-surface-low); padding: 10px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span class="input-label" style="font-size: 11px;">User ID</span>
                        <div style="font-family: var(--font-mono); font-size: 14px; font-weight: 600; color: var(--text-main); margin-top: 2px;">#${user.id}</div>
                    </div>
                    <div style="background: var(--bg-surface-low); padding: 10px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span class="input-label" style="font-size: 11px;">Account Status</span>
                        <div style="font-size: 13px; font-weight: 600; color: var(--success); margin-top: 2px;">Active / Enabled</div>
                    </div>
                    <div style="background: var(--bg-surface-low); padding: 10px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span class="input-label" style="font-size: 11px;">Account Created</span>
                        <div style="font-size: 12px; color: var(--text-sub); margin-top: 2px;">${new Date(user.created_at).toLocaleDateString()}</div>
                    </div>
                </div>
            </div>

            <!-- Role Permissions Matrix Card -->
            <div class="card">
                <h3 class="card-title">Role Authorization Matrix</h3>
                <p style="font-size: 12px; color: var(--text-sub); margin-bottom: 14px;">
                    Server-enforced REST API permissions for role: <strong>${roleTitle}</strong>
                </p>

                <div style="display: flex; flex-direction: column; gap: 8px; font-size: 12px;">
                    <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span>Dataset Triage Explorer & CVE Details</span>
                        <span style="color: var(--success); font-weight: 600;">Authorized</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span>Pre-Scoring CVSS & KEV Predictions (A1 & B2)</span>
                        <span style="color: var(--success); font-weight: 600;">Authorized</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span>Prioritization Sandbox (Mode 1 & Mode 2)</span>
                        <span style="color: ${user.role === 'researcher' ? 'var(--error)' : 'var(--success)'}; font-weight: 600;">
                            ${user.role === 'researcher' ? 'Restricted (Analyst/Admin Only)' : 'Authorized'}
                        </span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span>Local SHAP Feature Attributions</span>
                        <span style="color: var(--success); font-weight: 600;">Authorized</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span>User & Account Administration</span>
                        <span style="color: ${user.role === 'admin' ? 'var(--success)' : 'var(--error)'}; font-weight: 600;">
                            ${user.role === 'admin' ? 'Authorized' : 'Restricted (Admin Only)'}
                        </span>
                    </div>
                </div>
            </div>
        </div>
    `;

    const btnLogout = containerEl.querySelector('#btn-profile-logout');
    if (btnLogout) {
        btnLogout.addEventListener('click', async () => {
            await api.logout();
            state.setState({ currentUser: null, authToken: null });
            window.location.hash = 'home';
        });
    }
}
