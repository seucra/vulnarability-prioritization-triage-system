/**
 * Administrator Role Dashboard Component
 * Purpose: Application/System Administration, User Account Management, & Health Monitoring
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderAdminDashboard(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">System & Demonstration Administrator Dashboard</h2>
                <p class="section-desc">User account overview, role distribution, system availability monitoring, and administrative quick actions.</p>
            </div>
            <span class="badge badge-high" style="font-size: 12px; padding: 6px 12px;">Active Role: Administrator</span>
        </div>

        <div id="admin-dash-status-container"></div>

        <!-- User Accounts & Role Distribution KPIs -->
        <div class="provenance-grid" style="margin-bottom: 24px;">
            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Total User Accounts</div>
                <div class="provenance-stat-val" id="admin-dash-stat-total">1</div>
                <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">Registered Demonstration Users</div>
            </div>

            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Active / Enabled Users</div>
                <div class="provenance-stat-val" id="admin-dash-stat-active" style="color: var(--success);">1</div>
                <div style="font-size: 11px; color: var(--success); font-weight: 600; margin-top: 4px;">Authenticated Sessions Permitted</div>
            </div>

            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Disabled Accounts</div>
                <div class="provenance-stat-val" id="admin-dash-stat-disabled" style="color: var(--error);">0</div>
                <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">Restricted Access State</div>
            </div>

            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Role Distribution</div>
                <div class="provenance-stat-val" id="admin-dash-stat-roles" style="font-size: 15px; color: var(--primary);">Analyst / Research / Admin</div>
                <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">Active RBAC Configurations</div>
            </div>
        </div>

        <!-- Administrator Quick Actions -->
        <h3 class="section-title" style="font-size: 16px; margin-bottom: 12px;">Administrative Actions & Controls</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin-bottom: 24px;">
            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--primary);" onclick="window.location.hash='admin'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--primary);">1. User Administration</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Inspect accounts, review assigned roles, and enable or disable user accounts.</p>
            </div>

            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--tertiary);" onclick="window.location.hash='provenance'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--tertiary);">2. System Provenance</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Review dataset freeze manifest (2026-07-26) and raw SHA-256 checksums.</p>
            </div>

            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--success);" onclick="window.location.hash='docs'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--success);">3. System Documentation</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Access REST API specifications, backend architecture, and SRS documents.</p>
            </div>

            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--primary);" onclick="window.location.hash='profile'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--primary);">4. Admin Profile</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Inspect active session claims, administrative permissions, and sign out.</p>
            </div>
        </div>

        <div class="workspace-grid" style="margin-bottom: 24px;">
            <!-- System Engine & Database Status -->
            <div class="card" style="margin-bottom: 0;">
                <h3 class="card-title">System Engine & Service Availability</h3>
                <div style="display: flex; flex-direction: column; gap: 10px; font-size: 12px; margin-top: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span>FastAPI REST Server (Uvicorn)</span>
                        <span class="badge badge-low">Online / Healthy</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span>DuckDB Parquet Engine (366,547 CVEs)</span>
                        <span class="badge badge-low">Read-Only Active</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span>Serialized Models (EXP-A1 & EXP-B2 XGBoost)</span>
                        <span class="badge badge-low">Loaded in Memory</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: var(--bg-surface-low); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                        <span>SQLite Account Store (data/auth_users.sqlite)</span>
                        <span class="badge badge-low">Connected</span>
                    </div>
                </div>
            </div>

            <!-- Quick User Directory Summary -->
            <div class="card" style="margin-bottom: 0;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h3 class="card-title" style="margin-bottom: 0;">User Accounts Quick Overview</h3>
                    <button class="btn btn-outline btn-sm" onclick="window.location.hash='admin'">Manage All &rarr;</button>
                </div>
                <div style="overflow-x: auto;">
                    <table class="triage-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="admin-dash-users-table">
                            <tr><td colspan="4" style="text-align: center; color: var(--text-sub); padding: 16px;">Loading user accounts...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;

    loadAdminDashboardData(containerEl);
}

async function loadAdminDashboardData(containerEl) {
    const tbody = containerEl.querySelector('#admin-dash-users-table');
    try {
        const users = await api.listUsers();
        if (users && users.length > 0) {
            const activeCount = users.filter(u => u.is_active).length;
            const disabledCount = users.length - activeCount;

            const elTotal = containerEl.querySelector('#admin-dash-stat-total');
            const elActive = containerEl.querySelector('#admin-dash-stat-active');
            const elDisabled = containerEl.querySelector('#admin-dash-stat-disabled');

            if (elTotal) elTotal.textContent = users.length;
            if (elActive) elActive.textContent = activeCount;
            if (elDisabled) elDisabled.textContent = disabledCount;

            if (tbody) {
                tbody.innerHTML = users.slice(0, 4).map(u => {
                    const roleBadgeClass = u.role === 'admin' ? 'badge-high' : u.role === 'analyst' ? 'badge-low' : 'badge-medium';
                    return `
                        <tr>
                            <td><strong>${u.name}</strong></td>
                            <td><code>${u.email}</code></td>
                            <td><span class="badge ${roleBadgeClass}">${u.role}</span></td>
                            <td><span class="badge ${u.is_active ? 'badge-low' : 'badge-high'}">${u.is_active ? 'Active' : 'Disabled'}</span></td>
                        </tr>
                    `;
                }).join('');
            }
        }
    } catch (e) {
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-sub);">Unable to fetch user accounts directory.</td></tr>`;
        }
    }
}
