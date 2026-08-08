"""
API Router Assembly
Repository: seucra/vulnarability-prioritization-triage-system
"""

from fastapi import APIRouter
from backend.app.api.v1 import auth, explain, predict, prioritize, provenance, vulnerabilities

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(predict.router)
api_router.include_router(prioritize.router)
api_router.include_router(explain.router)
api_router.include_router(provenance.router)
