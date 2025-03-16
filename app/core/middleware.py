import time
from collections import defaultdict
from typing import Callable, Dict, Tuple, Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_429_TOO_MANY_REQUESTS


class RateLimitData:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = []  # List of timestamps


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for rate limiting API requests based on client IP address.
    
    Different rate limits can be configured for different path prefixes.
    """
    
    def __init__(
        self,
        app: FastAPI,
        default_limit: int = 100,
        default_window: int = 60,
        path_limits: Optional[Dict[str, Tuple[int, int]]] = None,
    ):
        super().__init__(app)
        self.default_limit = default_limit
        self.default_window = default_window
        self.path_limits = path_limits or {}
        
        # Store rate limiting data by client IP
        self.client_data: Dict[str, Dict[str, RateLimitData]] = defaultdict(dict)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get client IP
        client_ip = self._get_client_ip(request)
        if not client_ip:
            # If we can't identify the client, let the request through
            return await call_next(request)
        
        # Get the path and determine the rate limits
        path = request.url.path
        limit, window = self._get_limits_for_path(path)
        
        # Get or create rate limit data for this client and path
        if path not in self.client_data[client_ip]:
            self.client_data[client_ip][path] = RateLimitData(limit, window)
        rate_data = self.client_data[client_ip][path]
        
        # Check if the client has exceeded the rate limit
        current_time = time.time()
        
        # Remove old requests outside the current window
        window_start = current_time - window
        rate_data.requests = [t for t in rate_data.requests if t > window_start]
        
        # Check if the client has exceeded the limit
        if len(rate_data.requests) >= limit:
            headers = {
                "Retry-After": str(window),
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(window_start + window)),
            }
            
            return JSONResponse(
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many requests"},
                headers=headers,
            )
        
        # Add the current request
        rate_data.requests.append(current_time)
        
        # Set rate limit headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(limit - len(rate_data.requests))
        response.headers["X-RateLimit-Reset"] = str(int(current_time + window))
        
        return response
    
    def _get_client_ip(self, request: Request) -> Optional[str]:
        """Get the client's IP address."""
        # Check for X-Forwarded-For header
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # X-Forwarded-For can contain multiple IPs; the client IP is the first one
            return forwarded_for.split(",")[0].strip()
        
        # Fall back to the client's direct IP
        return request.client.host if request.client else None
    
    def _get_limits_for_path(self, path: str) -> Tuple[int, int]:
        """Get the rate limits for a specific path."""
        # Check if the path matches any of the configured path prefixes
        for prefix, (limit, window) in self.path_limits.items():
            if path.startswith(prefix):
                return limit, window
        
        # Fall back to the default limits
        return self.default_limit, self.default_window


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Middleware for CSRF protection.
    
    Ensures that POST, PUT, DELETE requests have a valid CSRF token.
    """
    
    def __init__(
        self,
        app: FastAPI,
        exclude_paths: Optional[list] = None,
    ):
        super().__init__(app)
        self.exclude_paths = exclude_paths or []
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip CSRF check for excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)
        
        # Only check CSRF for state-changing methods
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            # Check CSRF token in headers
            csrf_token = request.headers.get("X-CSRF-Token")
            cookie_token = request.cookies.get("csrf_token")
            
            if not csrf_token or not cookie_token or csrf_token != cookie_token:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF token missing or invalid"},
                )
        
        return await call_next(request)


def add_middlewares(app: FastAPI) -> None:
    """Add all middleware to the FastAPI application."""
    
    # Add rate limiting middleware
    app.add_middleware(
        RateLimitingMiddleware,
        default_limit=100,
        default_window=60,  # 100 requests per minute by default
        path_limits={
            "/api/v1/auth/login": (5, 60),  # 5 login attempts per minute
            "/api/v1/auth/register": (3, 60),  # 3 registration attempts per minute
            "/api/v1/auth/forgot-password": (3, 60),  # 3 password reset attempts per minute
        },
    )
    
    # Add CSRF middleware
    app.add_middleware(
        CSRFMiddleware,
        exclude_paths=[
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/oauth",
        ],
    ) 