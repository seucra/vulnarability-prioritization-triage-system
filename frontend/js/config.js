/**
 * Application Configuration (Environment Aware)
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

export const CONFIG = {
    API_BASE_URL: isLocalhost 
        ? "http://localhost:8000/api/v1" 
        : "https://vuln-triage-api.seucra.tech/api/v1",
    PUBLIC_FRONTEND_DOMAIN: "https://vuln-triage.seucra.tech",
    PUBLIC_API_DOMAIN: "https://vuln-triage-api.seucra.tech",
    REPOSITORY_NAME: "seucra/vulnarability-prioritization-triage-system",
    DEFAULT_PAGE_SIZE: 20,
    MAX_PAGE_SIZE: 100,
};
