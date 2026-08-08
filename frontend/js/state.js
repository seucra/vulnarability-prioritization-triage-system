/**
 * Reactive Application State Management
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

class AppState {
    constructor() {
        this.listeners = [];
        this.data = {
            // Active route tab
            activeTab: 'home',
            
            // Authentication state
            currentUser: null, // { id, email, name, role, created_at, is_active }
            authToken: localStorage.getItem('wdl_auth_token') || null,
            isSessionLoading: true,
            authError: null,
            
            // Explorer state
            searchParams: {
                q: '',
                cve_id: '',
                cwe_id: '',
                vendor: '',
                product: '',
                min_cvss: '',
                max_cvss: '',
                is_kev: '',
                min_epss: '',
                publication_year: '',
                page: 1,
                page_size: 20,
                sort_by: 'published',
                sort_dir: 'desc',
            },
            vulnerabilityResults: null,
            isExplorerLoading: false,
            explorerError: null,
            
            // Detail drawer state
            selectedCveId: null,
            cveDetail: null,
            isDetailLoading: false,
            detailError: null,
            
            // Prediction state
            predictionTab: 'cvss',
            cvssPredictionResult: null,
            kevPredictionResult: null,
            predictionError: null,
            isPredicting: false,
            
            // Prioritization state
            prioritizationInput: {
                cve_id: 'CVE-2021-44228',
                cvss_score: 10.0,
                epss_score: 0.95,
                is_kev: true,
                asset_criticality: 0.75,
            },
            prioritizationResult: null,
            isPrioritizing: false,
            prioritizationError: null,
            
            // Explanation state
            explanationResult: null,
            isExplaining: false,
            explanationError: null,
            
            // Provenance state
            provenanceData: null,
            isProvenanceLoading: false,
            provenanceError: null,
            
            // Admin workspace user list
            adminUsersList: null,
            isAdminLoading: false,
            adminError: null,
        };
    }

    subscribe(listener) {
        this.listeners.push(listener);
        return () => {
            this.listeners = this.listeners.filter(l => l !== listener);
        };
    }

    setState(updater) {
        if (typeof updater === 'function') {
            this.data = { ...this.data, ...updater(this.data) };
        } else {
            this.data = { ...this.data, ...updater };
        }
        this.notify();
    }

    getState() {
        return this.data;
    }

    notify() {
        this.listeners.forEach(listener => listener(this.data));
    }
}

export const state = new AppState();
