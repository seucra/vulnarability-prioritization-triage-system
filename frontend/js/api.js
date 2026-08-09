/**
 * REST API Client Layer
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { CONFIG } from './config.js';

class ApiClient {
    constructor() {
        this.baseUrl = CONFIG.API_BASE_URL;
        this.authToken = localStorage.getItem('wdl_auth_token') || null;
    }

    setAuthToken(token, user = null) {
        this.authToken = token;
        if (token) {
            localStorage.setItem('wdl_auth_token', token);
            if (user) {
                localStorage.setItem('wdl_user', JSON.stringify(user));
            }
        } else {
            localStorage.removeItem('wdl_auth_token');
            localStorage.removeItem('wdl_user');
        }
    }

    getAuthToken() {
        return this.authToken || localStorage.getItem('wdl_auth_token');
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...(options.headers || {})
        };

        const token = this.getAuthToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const config = {
            ...options,
            headers
        };

        try {
            const response = await fetch(url, config);
            
            if (response.status === 401) {
                // Invalid or expired token
                this.setAuthToken(null);
            }

            if (!response.ok) {
                let errorData;
                try {
                    errorData = await response.json();
                } catch (e) {
                    errorData = { detail: `HTTP ${response.status}: ${response.statusText}` };
                }
                const detail = typeof errorData.detail === 'string' 
                    ? errorData.detail 
                    : JSON.stringify(errorData.detail || 'API Request Failed');
                const err = new Error(detail);
                err.status = response.status;
                throw err;
            }

            return await response.json();
        } catch (error) {
            console.error(`API Request Error [${endpoint}]:`, error);
            throw error;
        }
    }

    // Authentication Endpoints
    async register(data) {
        return this.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    async login(data) {
        const res = await this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        if (res && res.access_token) {
            this.setAuthToken(res.access_token);
        }
        return res;
    }

    async logout() {
        try {
            await this.request('/auth/logout', { method: 'POST' });
        } catch (e) {
            // Ignore logout errors
        } finally {
            this.setAuthToken(null);
        }
    }

    async getMe() {
        return this.request('/auth/me', { method: 'GET' });
    }

    async listUsers() {
        return this.request('/auth/users', { method: 'GET' });
    }

    async updateUserStatus(userId, isActive) {
        return this.request(`/auth/users/${userId}/status`, {
            method: 'PATCH',
            body: JSON.stringify({ is_active: isActive })
        });
    }

    // Existing Research Endpoints
    async getVulnerabilities(params = {}) {
        const query = new URLSearchParams();
        Object.entries(params).forEach(([key, val]) => {
            if (val !== null && val !== undefined && val !== '') {
                query.append(key, val);
            }
        });
        const queryString = query.toString() ? `?${query.toString()}` : '';
        return this.request(`/vulnerabilities${queryString}`);
    }

    // Method alias for searchVulnerabilities
    async searchVulnerabilities(params = {}) {
        return this.getVulnerabilities(params);
    }

    async getVulnerabilityDetail(cveId) {
        return this.request(`/vulnerabilities/${encodeURIComponent(cveId)}`);
    }

    async predictCvss(payload, cveId = null) {
        const endpoint = cveId ? `/predict/cvss?cve_id=${encodeURIComponent(cveId)}` : '/predict/cvss';
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    }

    // Method alias for predictCVSS
    async predictCVSS(payload, cveId = null) {
        return this.predictCvss(payload, cveId);
    }

    async predictKev(payload) {
        return this.request('/predict/kev', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    }

    // Method alias for predictKEV
    async predictKEV(payload) {
        return this.predictKev(payload);
    }

    async prioritize(payload) {
        return this.request('/prioritize', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    }

    async explainCvss(payload) {
        return this.request('/explain/cvss', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    }

    // Method alias for explainCVSS
    async explainCVSS(payload) {
        return this.explainCvss(payload);
    }

    async explainKev(payload) {
        return this.request('/explain/kev', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    }

    // Method alias for explainKEV
    async explainKEV(payload) {
        return this.explainKev(payload);
    }

    async getProvenance() {
        return this.request('/provenance');
    }
}

export const api = new ApiClient();
