/**
 * Administration Workspace Component Controller (Admin Only)
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderAdminView(containerEl) {
    const s = state.getState();
    const user = s.currentUser;

    if (!user || user.role !== 'admin') {
        containerEl.innerHTML = `
            <div style="max-width: 540px; margin: 40px auto; text-align: center;">
                <div class="card" style="border-top: 4px solid var(--error);">
                    <h3 style="font-size: 18px; color: var(--error); margin-bottom: 12px;">HTTP 403 Forbidden — Access Restricted</h3>
                    <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 20px; line-height: 1.6;">
                        The Administration Workspace requires the <strong>Administrator</strong> role. 
                        Your current session is authenticated as <strong>${user ? user.role : 'Guest'}</strong>.
                    </p>
                    <button class="btn btn-outline" onclick="window.location.hash='dashboard'">Return to Dashboard</button>
                </div>
            </div>
        `;
        return;
    }

    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">System & User Administration</h2>
                <p class="section-desc">Inspect demonstration accounts, review assigned roles, and manage user account active states.</p>
            </div>
            <button class="btn btn-outline btn-sm" id="btn-refresh-users">Refresh User Accounts</button>
        </div>

        <div id="admin-status-container"></div>

        <div class="card">
            <h3 class="card-title">User Accounts Directory</h3>
            <div style="overflow-x: auto;">
                <table class="triage-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Full Name</th>
                            <th>Email Address</th>
                            <th>Role</th>
                            <th>Created Date</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="admin-users-table-body">
                        <tr>
                            <td colspan="7" style="text-align: center; color: var(--text-sub); padding: 24px;">
                                Loading user accounts from backend database...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;

    const btnRefresh = containerEl.querySelector('#btn-refresh-users');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', () => loadUsersList(containerEl));
    }

    loadUsersList(containerEl);
}

async function loadUsersList(containerEl) {
    const tbody = containerEl.querySelector('#admin-users-table-body');
    const statusContainer = containerEl.querySelector('#admin-status-container');
    if (!tbody) return;

    try {
        const users = await api.listUsers();
        state.setState({ adminUsersList: users });

        if (!users || users.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-sub);">No user accounts found.</td></tr>`;
            return;
        }

        tbody.innerHTML = users.map(u => {
            const roleBadgeClass = u.role === 'admin' ? 'badge-high' : u.role === 'analyst' ? 'badge-low' : 'badge-medium';
            const isSelfAdmin = u.role === 'admin';

            return `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight: 600;">#${u.id}</td>
                    <td><strong>${u.name}</strong></td>
                    <td><code>${u.email}</code></td>
                    <td><span class="badge ${roleBadgeClass}">${u.role}</span></td>
                    <td style="font-size: 12px; color: var(--text-sub);">${new Date(u.created_at).toLocaleDateString()}</td>
                    <td>
                        <span class="badge ${u.is_active ? 'badge-low' : 'badge-high'}">
                            ${u.is_active ? 'Active' : 'Disabled'}
                        </span>
                    </td>
                    <td>
                        ${isSelfAdmin ? `
                            <span style="font-size: 11px; color: var(--text-sub);">Primary Admin</span>
                        ` : `
                            <button class="btn btn-outline btn-sm toggle-status-btn" data-user-id="${u.id}" data-current-status="${u.is_active}">
                                ${u.is_active ? 'Disable' : 'Enable'} Account
                            </button>
                        `}
                    </td>
                </tr>
            `;
        }).join('');

        // Attach status toggle handlers
        tbody.querySelectorAll('.toggle-status-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const userId = parseInt(btn.getAttribute('data-user-id'), 10);
                const currentStatus = btn.getAttribute('data-current-status') === 'true';
                btn.disabled = true;

                try {
                    await api.updateUserStatus(userId, !currentStatus);
                    loadUsersList(containerEl);
                } catch (err) {
                    if (statusContainer) {
                        statusContainer.innerHTML = `
                            <div class="error-banner" style="margin-bottom: 16px;">
                                <strong>Status Update Error:</strong> ${err.message}
                            </div>
                        `;
                    }
                }
            });
        });
    } catch (err) {
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--error);">Failed to load user accounts: ${err.message}</td></tr>`;
        }
    }
}
