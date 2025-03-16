from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.endpoints import auth, users
from app.core.config import settings
from app.core.middleware import add_middlewares

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Authentication System API",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Set up CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add custom middlewares (rate limiting, CSRF protection)
add_middlewares(app)

# Include routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(users.router, prefix=settings.API_V1_STR)

@app.get("/")
async def root():
    return {"message": "Authentication System API"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"} 