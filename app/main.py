from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.api_v1.api import api_router
from app.core.config import settings
from app.core.middleware import add_middlewares
from app.db.init_db import init_db
from app.db.session import SessionLocal

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Authentication System API",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Initialize database tables
db = SessionLocal()
try:
    init_db(db)
finally:
    db.close()

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

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/")
async def root():
    return {"message": "Authentication System API"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"} 