Project Overview
Development of a comprehensive authentication system using FastAPI with OAuth (Facebook, Google), JWT tokens, and multi-factor authentication (MFA) through email verification.
Technology Stack

Backend Framework: FastAPI
Authentication: OAuth 2.0, JWT
Database: PostgreSQL (Neon Platform)
Cloud Services: Firebase (hosting), Amazon SES (email)

Core Features
1. User Registration

Functionality: Allow users to create new accounts with mandatory email verification
Requirements:

Collect and validate required user information:

First Name (only alphabetic characters allowed)
Last Name (only alphabetic characters allowed)
Date of Birth (with appropriate age validation)
Gender (selection from predefined options)
Email (valid format with domain verification)
Mobile Number (Bangladeshi format validation, e.g., +880XXXXXXXXXX)


Enforce password strength requirements
Generate and send email verification link via Amazon SES
Keep account in "pending" state until email is verified
Prohibit login until email verification is complete
Store encrypted passwords only (no plaintext)
Create user record in PostgreSQL database after successful validation
Implement proper error handling with specific error messages for each validation failure



2. User Login

Functionality: Authenticate users through multiple methods
Requirements:

Support traditional email/password login
Integrate OAuth login via Facebook
Integrate OAuth login via Google
Issue JWT token upon successful authentication
Implement token refresh mechanism
Enforce MFA for sensitive operations
Maintain login audit trail



3. Password Management

Functionality: Allow users to reset forgotten passwords
Requirements:

Provide "Forgot Password" flow
Generate secure, time-limited reset tokens
Send password reset links via Amazon SES
Validate reset tokens
Allow password changes with proper authentication
Enforce password history policy



4. Multi-Factor Authentication (MFA)

Functionality: Add an extra layer of security through email verification
Requirements:

Generate time-limited verification codes
Send verification codes via Amazon SES
Verify submitted codes
Allow users to enable/disable MFA
Enforce MFA for sensitive operations
Provide bypass mechanisms for account recovery



API Endpoints
Authentication Endpoints

POST /api/auth/register: Create new user account
POST /api/auth/verify-email: Verify email address with token
POST /api/auth/login: Traditional login with email/password
GET /api/auth/oauth/google: Initiate Google OAuth flow
GET /api/auth/oauth/facebook: Initiate Facebook OAuth flow
GET /api/auth/oauth/callback: OAuth provider callback endpoint
POST /api/auth/refresh: Refresh JWT token
POST /api/auth/logout: Invalidate current token

Password Management Endpoints

POST /api/auth/forgot-password: Initiate password reset
POST /api/auth/reset-password: Complete password reset
PUT /api/auth/change-password: Change password (authenticated)

MFA Endpoints

POST /api/auth/mfa/enable: Enable MFA for account
POST /api/auth/mfa/verify: Verify MFA code
POST /api/auth/mfa/disable: Disable MFA (requires verification)

Security Requirements

Store only hashed passwords (bcrypt/Argon2)
Implement rate limiting for login attempts
Set appropriate JWT expiration times
Use HTTPS for all connections
Implement CSRF protection
Sanitize all inputs to prevent injection attacks
Log security events for audit purposes

Database Schema
Users Table

id (UUID, primary key)
first_name (varchar, alphabetic characters only)
last_name (varchar, alphabetic characters only)
date_of_birth (date)
gender (enum: 'male', 'female', 'other', 'prefer_not_to_say')
email (varchar, unique)
mobile (varchar, Bangladeshi format)
password_hash (varchar)
created_at (timestamp)
updated_at (timestamp)
last_login (timestamp)
is_active (boolean)
is_email_verified (boolean)
mfa_enabled (boolean)

OAuth Accounts Table

id (UUID, primary key)
user_id (foreign key to Users)
provider (Google/Facebook)
provider_user_id
created_at

Access Tokens Table

id (UUID, primary key)
user_id (foreign key to Users)
token_hash
expires_at
created_at

Refresh Tokens Table

id (UUID, primary key)
user_id (foreign key to Users)
token_hash
expires_at
created_at
is_revoked

Verification Tokens Table

id (UUID, primary key)
user_id (foreign key to Users)
token_hash
type (enum: 'email_verification', 'password_reset', 'mfa')
expires_at
created_at
is_used (boolean)

Deployment Architecture

FastAPI application hosted on Firebase Hosting
PostgreSQL database on Neon Platform
Email services through Amazon SES
Static assets and auxiliary functions on Firebase