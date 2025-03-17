# Step 1: Project Structure and Dependencies

In this step, we set up the basic project structure and dependencies for our authentication system.

## Project Structure

We created a comprehensive directory structure following best practices for FastAPI applications:

```
authsys/
├── alembic/                  # Database migration scripts
│   ├── versions/             # Migration versions
│   ├── env.py                # Alembic environment configuration
│   └── script.py.mako        # Migration script template
├── app/                      # Main application package
│   ├── api/                  # API endpoints and dependencies
│   │   ├── dependencies/     # Reusable dependencies for API endpoints
│   │   └── endpoints/        # API endpoint routers
│   ├── core/                 # Core application components
│   │   └── config.py         # Application configuration
│   ├── db/                   # Database related code
│   │   ├── base.py           # Import all models for Alembic
│   │   ├── base_class.py     # SQLAlchemy base class
│   │   └── session.py        # Database session management
│   ├── models/               # SQLAlchemy ORM models
│   │   ├── user.py           # User model
│   │   ├── oauth_account.py  # OAuth account model
│   │   └── token.py          # Token models (access, refresh, verification)
│   ├── schemas/              # Pydantic schemas for request/response validation
│   ├── services/             # Business logic services
│   ├── utils/                # Utility functions
│   ├── tests/                # Test directory
│   │   ├── unit/             # Unit tests
│   │   └── integration/      # Integration tests
│   └── main.py               # FastAPI application entry point
├── .env.example              # Example environment variables
├── alembic.ini               # Alembic configuration
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

## Database Models

We defined the following database models according to the schema in the roadmap:

1. **User Model**: Stores user information including personal details, authentication status, and security settings.
2. **OAuthAccount Model**: Links users to their OAuth provider accounts (Google, Facebook).
3. **Token Models**:
   - **AccessToken**: Short-lived tokens for API access
   - **RefreshToken**: Long-lived tokens for refreshing access tokens
   - **VerificationToken**: Time-limited tokens for email verification, password reset, and MFA

## Configuration

We set up a comprehensive configuration system using Pydantic's BaseSettings, which allows loading configuration from environment variables. The configuration includes:

- API settings
- Security settings (JWT, token expiration)
- CORS settings
- Database connection settings
- Email settings (AWS SES)
- OAuth provider settings

## Database Migration

We configured Alembic for database migrations, which will allow us to:
- Track changes to the database schema
- Apply migrations in a controlled manner
- Roll back changes if needed

## Next Steps

In the next step, we will implement:
1. User registration with validation
2. Email verification
3. Basic authentication endpoints
