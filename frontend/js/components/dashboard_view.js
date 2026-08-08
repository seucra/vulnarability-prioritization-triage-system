/**
 * Shared System Dashboard Router Shell
 * Purpose: Determines authenticated user role and renders role-specific dashboard component
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { state } from '../state.js';
import { renderAnalystDashboard } from './analyst_dashboard.js';
import { renderResearcherDashboard } from './researcher_dashboard.js';
import { renderAdminDashboard } from './admin_dashboard.js';

export function renderDashboardView(containerEl) {
    const s = state.getState();
    const user = s.currentUser;

    if (!user) {
        containerEl.innerHTML = `
            <div style="max-width: 560px; margin: 40px auto; text-align: center;">
                <div class="card" style="padding: 32px; border-top: 4px solid var(--primary);">
                    <div style="background: var(--bg-surface-container); padding: 12px; border-radius: var(--radius-full); width: 48px; height: 48px; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px; color: var(--primary);">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                    </div>
                    <h3 style="font-size: 20px; font-weight: 700; color: var(--text-main); margin-bottom: 8px;">Role-Specific System Dashboard</h3>
                    <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6; margin-bottom: 24px;">
                        The system dashboard customizes operational workflows, research benchmarks, and administrative controls based on your authenticated role (Security Analyst, Researcher, or Administrator).
                    </p>
                    <div style="display: flex; gap: 12px; justify-content: center;">
                        <button class="btn btn-primary" onclick="window.location.hash='login'" style="padding: 10px 20px;">
                            Sign In to Access Dashboard
                        </button>
                        <button class="btn btn-outline" onclick="window.location.hash='register'" style="padding: 10px 20px;">
                            Register Demonstration Account
                        </button>
                    </div>
                </div>
            </div>
        `;
        return;
    }

    // Role-based routing to specific dashboard components
    if (user.role === 'analyst') {
        renderAnalystDashboard(containerEl);
    } else if (user.role === 'researcher') {
        renderResearcherDashboard(containerEl);
    } else if (user.role === 'admin') {
        renderAdminDashboard(containerEl);
    } else {
        renderAnalystDashboard(containerEl);
    }
}
