/**
 * Navbar Component Controller (Role-Aware)
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderNavbar(containerEl) {
    const updateNavbarUI = (s) => {
        const user = s.currentUser;
        const isLoggedIn = !!user;
        const role = user ? user.role : null;

        const roleTitle = role === 'admin' ? 'Admin' : role === 'analyst' ? 'Analyst' : 'Researcher';
        const roleBadgeClass = role === 'admin' ? 'badge-high' : role === 'analyst' ? 'badge-low' : 'badge-medium';

        containerEl.innerHTML = `
            <div class="app-header">
                <div class="brand-title" style="cursor: pointer;" onclick="window.location.hash='home'">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <path d="m9 12 2 2 4-4"/>
                    </svg>
                    <div>
                        <div class="brand-text">Vulnerability Prioritization</div>
                        <div class="repo-badge">seucra/vulnarability-prioritization-triage-system</div>
                    </div>
                </div>

                <nav class="nav-tabs" id="nav-tabs-wrapper">
                    <!-- Public Navigation Group -->
                    <div class="nav-group">
                        <button class="nav-tab ${s.activeTab === 'home' ? 'active' : ''}" data-tab="home">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
                            Home
                        </button>
                        <button class="nav-tab ${s.activeTab === 'about' ? 'active' : ''}" data-tab="about">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                            About
                        </button>
                        <button class="nav-tab ${s.activeTab === 'docs' ? 'active' : ''}" data-tab="docs">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
                            Docs
                        </button>
                    </div>

                    ${isLoggedIn ? `
                        <div class="nav-divider"></div>

                        <!-- Authenticated Application Workspaces -->
                        <div class="nav-group">
                            <button class="nav-tab ${s.activeTab === 'dashboard' ? 'active' : ''}" data-tab="dashboard">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                                Dashboard
                            </button>
                            <button class="nav-tab ${s.activeTab === 'explorer' ? 'active' : ''}" data-tab="explorer">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                                Explorer
                            </button>
                            <button class="nav-tab ${s.activeTab === 'predict' ? 'active' : ''}" data-tab="predict">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                                Predictions
                            </button>

                            ${role === 'analyst' || role === 'admin' ? `
                                <button class="nav-tab ${s.activeTab === 'prioritize' ? 'active' : ''}" data-tab="prioritize">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                                    Prioritization
                                </button>
                            ` : ''}

                            <button class="nav-tab ${s.activeTab === 'explain' ? 'active' : ''}" data-tab="explain">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                                Explainability
                            </button>

                            <button class="nav-tab ${s.activeTab === 'provenance' ? 'active' : ''}" data-tab="provenance">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                Provenance
                            </button>

                            ${role === 'admin' ? `
                                <button class="nav-tab ${s.activeTab === 'admin' ? 'active' : ''}" data-tab="admin" style="color: var(--primary);">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                                    Admin
                                </button>
                            ` : ''}
                        </div>

                        <div class="nav-divider"></div>

                        <!-- User Profile & Logout Group -->
                        <div class="nav-group">
                            <button class="nav-tab nav-tab-auth ${s.activeTab === 'profile' ? 'active' : ''}" data-tab="profile">
                                <span class="badge ${roleBadgeClass}" style="font-size: 10px; padding: 2px 6px;">${roleTitle}</span>
                                ${user.name.split(' ')[0]}
                            </button>
                            <button class="nav-tab" id="nav-btn-logout" title="Sign Out" style="padding: 6px 10px;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--error);"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                            </button>
                        </div>
                    ` : `
                        <div class="nav-divider"></div>

                        <!-- Logged Out Auth Group -->
                        <div class="nav-group">
                            <button class="nav-tab nav-tab-auth ${s.activeTab === 'login' ? 'active' : ''}" data-tab="login">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
                                Sign In
                            </button>
                            <button class="nav-tab nav-tab-auth ${s.activeTab === 'register' ? 'active' : ''}" data-tab="register" style="background-color: var(--primary-container); color: var(--on-primary-container);">
                                Register
                            </button>
                        </div>
                    `}
                </nav>

                <div class="header-meta">
                    <div class="status-indicator">
                        <span class="dot-green"></span>
                        <span id="header-freeze-status">
                            ${isLoggedIn ? `Role: ${roleTitle}` : 'Demonstration Mode'}
                        </span>
                    </div>
                </div>
            </div>
        `;

        // Attach click listeners to tabs
        containerEl.querySelectorAll('.nav-tab[data-tab]').forEach(btn => {
            btn.addEventListener('click', () => {
                const tabName = btn.getAttribute('data-tab');
                if (tabName) {
                    window.location.hash = tabName;
                }
            });
        });

        // Attach logout listener
        const btnLogout = containerEl.querySelector('#nav-btn-logout');
        if (btnLogout) {
            btnLogout.addEventListener('click', async () => {
                await api.logout();
                state.setState({ currentUser: null, authToken: null });
                window.location.hash = 'home';
            });
        }
    };

    // Render initial UI and subscribe to state
    updateNavbarUI(state.getState());
    state.subscribe(s => updateNavbarUI(s));
}
