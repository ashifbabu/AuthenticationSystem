# Authentication System

A comprehensive authentication system built with FastAPI, featuring OAuth (Facebook, Google), JWT tokens, and multi-factor authentication (MFA) through email verification.

## Features

- **User Registration**: Email verification, strict input validation
- **Multiple Authentication Methods**: Email/password, Google OAuth, Facebook OAuth
- **JWT Authentication**: Secure token-based authentication with refresh mechanism
- **Password Management**: Secure reset and change flows
- **Multi-Factor Authentication**: Additional security layer via email verification
- **Security**: HTTPS, rate limiting, CSRF protection, input sanitization

## Technology Stack

- **Backend Framework**: FastAPI
- **Authentication**: OAuth 2.0, JWT
- **Database**: PostgreSQL (Neon Platform)
- **Cloud Services**: Firebase (hosting), Amazon SES (email)

## Getting Started

### Prerequisites

- Python 3.8+
- PostgreSQL database
- AWS account (for Amazon SES)
- Firebase account
- OAuth credentials (Google, Facebook)

### Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd authsys
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up environment variables (create a `.env` file in the root directory):
   ```
   DATABASE_URL=postgresql://user:password@localhost/authsys
   SECRET_KEY=your-secret-key
   AWS_ACCESS_KEY=your-aws-access-key
   AWS_SECRET_KEY=your-aws-secret-key
   AWS_REGION=your-aws-region
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   FACEBOOK_CLIENT_ID=your-facebook-client-id
   FACEBOOK_CLIENT_SECRET=your-facebook-client-secret
   ```

5. Run migrations:
   ```
   alembic upgrade head
   ```

6. Start the development server:
   ```
   uvicorn app.main:app --reload
   ```

## API Documentation

After starting the server, access the interactive API documentation at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Testing

Run the test suite:
```
pytest
```

Run tests with coverage report:
```
coverage run -m pytest
coverage report
```

## Deployment

The application is configured for deployment on Firebase Hosting with GitHub Actions for CI/CD.

## License

[MIT License](LICENSE) 