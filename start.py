import uvicorn
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.routers import auth

app = FastAPI(
    title="HackIt SSO",
    description="A centralized authentication service for the HackIt organization.",
    version="1.0.0"
)

# Security middleware - Only allow HackIt domains
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=[
        "hackit.tw",
        "*.hackit.tw",
        "localhost",
        "127.0.0.1",
        "0.0.0.0"
    ]
)

# CORS middleware for cross-domain SSO support
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://hackit.tw",
        "https://*.hackit.tw",
        "http://localhost:*",
        "http://127.0.0.1:*",
        "http://localhost:3000",
        "http://localhost:3001", 
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Requested-With",
        "X-SSO-Domain",
        "X-SSO-Timestamp",
        "X-SSO-Signature"
    ],
    expose_headers=[
        "X-SSO-Expires-At",
        "X-SSO-Refresh-Token"
    ]
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Setup templates
templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Redirect to auth login page."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/auth/", status_code=302)

# Health check endpoint for SSO monitoring
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring SSO service status."""
    return {
        "status": "healthy",
        "service": "HackIt SSO",
        "version": "1.0.0"
    }

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# Include OIDC router for OpenID Connect support
from app.routers import oidc
app.include_router(oidc.router, tags=["OIDC"])


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7411) 