/**
 * Navbar Component Controller (Concise, Role-Aware, & Mobile Responsive)
 * Visual Identity: Warm stone, charcoal, restrained antique-gold accent
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderNavbar(containerEl) {
    let isMobileMenuOpen = false;

    const updateNavbarUI = (s) => {
        const user = s.currentUser;
        const isLoggedIn = !!user;
        const role = user ? user.role : null;

        const roleTitle = role === 'admin' ? 'Admin' : role === 'analyst' ? 'Analyst' : 'Researcher';
        const roleBadgeClass = role === 'admin' ? 'badge-critical' : role === 'analyst' ? 'badge-neutral' : 'badge-neutral';

        containerEl.innerHTML = `
            <header class="app-header">
                <a class="brand-wrapper" onclick="window.location.hash='home'">
                    <span class="brand-mark" aria-hidden="true">VTS</span>
                    <div class="brand-meta">
                        <span class="brand-title">Vulnerability Prioritization</span>
                        <span class="brand-subtitle">Academic Research Instrument</span>
                    </div>
                </a>

                <button class="mobile-nav-toggle" id="mobile-nav-toggle" aria-label="Toggle navigation menu" aria-expanded="${isMobileMenuOpen}" aria-controls="nav-tabs-wrapper">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        ${isMobileMenuOpen 
                            ? '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>' 
                            : '<line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>'}
                    </svg>
                    <span>${isMobileMenuOpen ? 'Close' : 'Menu'}</span>
                </button>

                <nav class="nav-tabs ${isMobileMenuOpen ? 'is-open' : ''}" id="nav-tabs-wrapper" aria-label="Primary Navigation">
                    <!-- Principal Operational & Research Workspaces -->
                    <div class="nav-group">
                        <button class="nav-tab ${s.activeTab === 'home' || s.activeTab === 'dashboard' ? 'active' : ''}" data-tab="${isLoggedIn ? 'dashboard' : 'home'}">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                            Overview
                        </button>
                        <button class="nav-tab ${s.activeTab === 'explorer' ? 'active' : ''}" data-tab="explorer">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                            Explorer
                        </button>
                        <button class="nav-tab ${s.activeTab === 'predict' ? 'active' : ''}" data-tab="predict">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                            Predict
                        </button>
                        <button class="nav-tab ${s.activeTab === 'prioritize' ? 'active' : ''}" data-tab="prioritize">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                            Prioritize
                        </button>
                        ${isLoggedIn && (role === 'analyst' || role === 'admin') ? `
                            <button class="nav-tab ${s.activeTab === 'triage' ? 'active' : ''}" data-tab="triage">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
                                Batch Triage
                            </button>
                        ` : ''}
                        <button class="nav-tab ${s.activeTab === 'provenance' ? 'active' : ''}" data-tab="provenance">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                            Research
                        </button>
                        <button class="nav-tab ${s.activeTab === 'docs' ? 'active' : ''}" data-tab="docs">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
                            Docs
                        </button>
                    </div>

                    <div class="nav-divider" role="separator"></div>

                    <!-- Account / Session Controls -->
                    <div class="nav-group">
                        ${isLoggedIn ? `
                            ${role === 'admin' ? `
                                <button class="nav-tab ${s.activeTab === 'admin' ? 'active' : ''}" data-tab="admin" title="Administration Directory">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                                    Admin
                                </button>
                            ` : ''}
                            <button class="nav-tab nav-tab-auth ${s.activeTab === 'profile' ? 'active' : ''}" data-tab="profile" title="View Account Profile">
                                <span class="badge ${roleBadgeClass}" style="font-size: 10px;">${roleTitle}</span>
                                <span>${escapeHtml(user.name.split(' ')[0])}</span>
                            </button>
                            <button class="nav-tab" id="nav-btn-logout" title="Sign Out">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                                <span class="mobile-only-text">Sign Out</span>
                            </button>
                        ` : `
                            <button class="nav-tab nav-tab-auth ${s.activeTab === 'login' ? 'active' : ''}" data-tab="login">
                                Sign In
                            </button>
                            <button class="nav-tab nav-tab-btn-primary ${s.activeTab === 'register' ? 'active' : ''}" data-tab="register">
                                Register
                            </button>
                        `}
                    </div>
                </nav>

                <div class="header-meta">
                    <div class="status-pill">
                        <span class="status-dot"></span>
                        <span id="header-freeze-status">
                            ${isLoggedIn ? `${roleTitle}` : 'Demo Mode'}
                        </span>
                    </div>
                </div>
            </header>
        `;

        // Mobile menu toggle
        const mobileToggle = containerEl.querySelector('#mobile-nav-toggle');
        if (mobileToggle) {
            mobileToggle.addEventListener('click', (e) => {
                e.stopPropagation();
                isMobileMenuOpen = !isMobileMenuOpen;
                updateNavbarUI(state.getState());
            });
        }

        // Click listeners on nav buttons
        containerEl.querySelectorAll('.nav-tab[data-tab]').forEach(btn => {
            btn.addEventListener('click', () => {
                const tab = btn.getAttribute('data-tab');
                if (tab) {
                    isMobileMenuOpen = false;
                    window.location.hash = tab;
                }
            });
        });

        // Logout listener
        const btnLogout = containerEl.querySelector('#nav-btn-logout');
        if (btnLogout) {
            btnLogout.addEventListener('click', async () => {
                isMobileMenuOpen = false;
                await api.logout();
                state.setCurrentUser(null, null);
                window.location.hash = 'home';
            });
        }
    };

    // Close menu on escape
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && isMobileMenuOpen) {
            isMobileMenuOpen = false;
            updateNavbarUI(state.getState());
        }
    });

    updateNavbarUI(state.getState());
    state.subscribe(s => updateNavbarUI(s));
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
