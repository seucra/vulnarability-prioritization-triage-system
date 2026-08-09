/**
 * SPA Application Main Entrypoint & Router (WDL-2 Auth & Guarded)
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from './api.js';
import { renderNavbar } from './components/navbar.js';
import { renderLandingView } from './components/landing_view.js';
import { renderAboutView } from './components/about_view.js';
import { renderDocsView } from './components/docs_view.js';
import { renderDashboardView } from './components/dashboard_view.js';
import { renderExplorer } from './components/explorer.js';
import { renderDetailModal } from './components/detail_modal.js';
import { renderPredictionView } from './components/prediction_view.js';
import { renderPrioritizationView } from './components/prioritization_view.js';
import { renderExplanationView } from './components/explanation_view.js';
import { renderProvenanceView } from './components/provenance_view.js';
import { renderLoginView } from './components/login_view.js';
import { renderRegisterView } from './components/register_view.js';
import { renderProfileView } from './components/profile_view.js';
import { renderAdminView } from './components/admin_view.js';
import { renderFaqView } from './components/faq_view.js';
import { renderContactView } from './components/contact_view.js';
import { state } from './state.js';

const PUBLIC_ROUTES = ['home', 'about', 'docs', 'faq', 'contact', 'login', 'register'];
const PROTECTED_ROUTES = ['dashboard', 'explorer', 'predict', 'prioritize', 'explain', 'provenance', 'admin', 'profile'];
const VALID_ROUTES = [...PUBLIC_ROUTES, ...PROTECTED_ROUTES];

function resolveRouteFromHash() {
    const rawHash = window.location.hash.replace('#', '').trim();
    if (!rawHash || rawHash === '') return 'home';
    return VALID_ROUTES.includes(rawHash) ? rawHash : 'home';
}

function checkRouteAuthorization(route, user) {
    if (PUBLIC_ROUTES.includes(route)) {
        return { allowed: true };
    }

    if (!user) {
        return { allowed: false, reason: 'unauthenticated', target: 'login' };
    }

    if (route === 'prioritize' && user.role === 'researcher') {
        return { allowed: false, reason: 'forbidden', roleRequired: 'Security Analyst or Administrator' };
    }

    if (route === 'admin' && user.role !== 'admin') {
        return { allowed: false, reason: 'forbidden', roleRequired: 'Administrator' };
    }

    return { allowed: true };
}

document.addEventListener('DOMContentLoaded', async () => {
    console.log("Initializing Vulnerability Prioritization Triage System SPA Router & Auth...");

    // Mount Navbar
    const navContainer = document.getElementById('navbar-container');
    if (navContainer) {
        renderNavbar(navContainer);
    }

    // Mount Detail Modal Drawer
    const modalContainer = document.getElementById('detail-modal-container');
    if (modalContainer) {
        renderDetailModal(modalContainer);
    }

    // Map View Elements
    const views = {
        home: document.getElementById('view-home'),
        about: document.getElementById('view-about'),
        docs: document.getElementById('view-docs'),
        dashboard: document.getElementById('view-dashboard'),
        explorer: document.getElementById('view-explorer'),
        predict: document.getElementById('view-predict'),
        prioritize: document.getElementById('view-prioritize'),
        explain: document.getElementById('view-explain'),
        provenance: document.getElementById('view-provenance'),
        login: document.getElementById('view-login'),
        register: document.getElementById('view-register'),
        profile: document.getElementById('view-profile'),
        admin: document.getElementById('view-admin'),
        faq: document.getElementById('view-faq'),
        contact: document.getElementById('view-contact'),
    };

    // Render Component Contents into Views
    if (views.home) renderLandingView(views.home);
    if (views.about) renderAboutView(views.about);
    if (views.docs) renderDocsView(views.docs);
    if (views.dashboard) renderDashboardView(views.dashboard);
    if (views.explorer) renderExplorer(views.explorer);
    if (views.predict) renderPredictionView(views.predict);
    if (views.prioritize) renderPrioritizationView(views.prioritize);
    if (views.explain) renderExplanationView(views.explain);
    if (views.provenance) renderProvenanceView(views.provenance);
    if (views.login) renderLoginView(views.login);
    if (views.register) renderRegisterView(views.register);
    if (views.profile) renderProfileView(views.profile);
    if (views.admin) renderAdminView(views.admin);
    if (views.faq) renderFaqView(views.faq);
    if (views.contact) renderContactView(views.contact);

    // Session Recovery from localStorage
    const savedToken = api.getAuthToken();
    if (savedToken) {
        try {
            const userContext = await api.getMe();
            state.setState({ currentUser: userContext, isSessionLoading: false });
        } catch (e) {
            console.warn("Session recovery failed, clearing token.");
            api.setAuthToken(null);
            state.setState({ currentUser: null, isSessionLoading: false });
        }
    } else {
        state.setState({ isSessionLoading: false });
    }

    // Handle Route Navigation & Client Guards
    const handleNavigation = () => {
        const route = resolveRouteFromHash();
        const s = state.getState();
        const authCheck = checkRouteAuthorization(route, s.currentUser);

        if (!authCheck.allowed) {
            if (authCheck.reason === 'unauthenticated') {
                window.location.hash = 'login';
                return;
            } else if (authCheck.reason === 'forbidden') {
                state.setState({ activeTab: route });
                const activeView = views[route];
                if (activeView) {
                    activeView.innerHTML = `
                        <div style="max-width: 560px; margin: 40px auto; text-align: center;">
                            <div class="card" style="border-top: 4px solid var(--error); padding: 32px;">
                                <h3 style="font-size: 18px; color: var(--error); margin-bottom: 12px;">HTTP 403 Forbidden — Role Access Denied</h3>
                                <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 20px; line-height: 1.6;">
                                    The requested workspace <code>#${route}</code> requires the <strong>${authCheck.roleRequired}</strong> role. 
                                    Your active session is authenticated as <strong>${s.currentUser ? s.currentUser.role : 'Guest'}</strong>.
                                </p>
                                <button class="btn btn-outline" onclick="window.location.hash='dashboard'">Return to Dashboard</button>
                            </div>
                        </div>
                    `;
                }
                return;
            }
        }

        // Re-render dynamically updated components when navigating
        if (route === 'dashboard' && views.dashboard) renderDashboardView(views.dashboard);
        if (route === 'profile' && views.profile) renderProfileView(views.profile);
        if (route === 'admin' && views.admin) renderAdminView(views.admin);

        state.setState({ activeTab: route });
        window.scrollTo(0, 0);
    };

    // Initial navigation check & hashchange listener
    handleNavigation();
    window.addEventListener('hashchange', handleNavigation);

    // Reactive View Switcher
    let prevUser = state.getState().currentUser;
    state.subscribe(s => {
        // Re-render dashboard if auth user state changed
        if (s.currentUser !== prevUser) {
            prevUser = s.currentUser;
            if (views.dashboard) renderDashboardView(views.dashboard);
            if (views.profile) renderProfileView(views.profile);
            if (views.admin) renderAdminView(views.admin);
        }

        Object.entries(views).forEach(([routeName, el]) => {
            if (el) {
                if (routeName === s.activeTab) {
                    el.classList.add('active');
                } else {
                    el.classList.remove('active');
                }
            }
        });
    });
});
