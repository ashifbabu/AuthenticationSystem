# Testing Strategy for Authentication System

This document outlines the testing strategy and implementation for our authentication system.

## Test Categories

### Unit Tests

Located in `app/tests/unit/`, these tests focus on isolated components:

- **Schema Validation Tests**: Verify Pydantic schemas properly validate input data
- **Security Utility Tests**: Test password hashing, token generation, and other security utilities
- **Helper Function Tests**: Ensure utility functions work correctly in isolation

### Integration Tests

Located in `app/tests/integration/`, these tests verify the interaction between components:

- **API Endpoint Tests**: Test the behavior of API endpoints with various inputs
- **Authentication Flow Tests**: Verify complete authentication workflows
- **Database Interaction Tests**: Check CRUD operations against the database

## Test Structure

Each test module follows a consistent structure:

1. **Setup**: Fixtures for creating test data and environments
2. **Test Cases**: Individual test functions for each scenario
3. **Cleanup**: Automatic cleanup of test resources (handled by pytest fixtures)

## Test Files

### Authentication Tests (`test_auth.py`)

Tests for core authentication functionality:

- User registration
- Email verification
- Login and token generation
- Token refresh
- Logout

### Password Management Tests (`test_password.py`)

Tests for password-related functionality:

- Password change
- Password reset flow (request, token validation, reset)
- Password validation rules

### Multi-Factor Authentication Tests (`test_mfa.py`)

Tests for MFA implementation:

- MFA enabling
- MFA code verification
- MFA disabling
- MFA enforcement during login

### Account Lockout Tests (`test_account_lockout.py`)

Tests for account security features:

- Failed login attempt tracking
- Account lockout after multiple failures
- Account status checking
- Administrative account unlocking

### OAuth Tests (`test_oauth.py`)

Tests for OAuth authentication:

- OAuth login redirection
- OAuth callback handling
- Account linking with OAuth providers
- OAuth profile information retrieval

### User Profile Tests (`test_users.py`)

Tests for user profile management:

- Profile retrieval
- Profile updating
- OAuth account management
- User deletion

## Test Fixtures

Key fixtures defined in `conftest.py`:

- **`db_session`**: Provides a database session for tests
- **`client`**: Provides a FastAPI TestClient
- **`test_user`**: Creates a standard user for testing
- **`verified_test_user`**: Creates a user with verified email
- **`test_auth_headers`**: Provides authentication headers for API requests
- **`test_admin_headers`**: Provides admin authentication headers

## Testing Best Practices

1. **Test Isolation**: Each test should be independent and not rely on state from other tests
2. **Use Fixtures**: Utilize pytest fixtures for common setup and teardown
3. **Mock External Services**: Use mocks for external services like email
4. **Assert Outcomes**: Check both response status and content
5. **Test Edge Cases**: Include tests for error conditions and edge cases
6. **Test Security**: Verify that security controls work as expected

## Running Tests

To run all tests:

```bash
pytest
```

To run specific test categories:

```bash
pytest app/tests/unit/           # Run unit tests only
pytest app/tests/integration/    # Run integration tests only
```

To run specific test files:

```bash
pytest app/tests/integration/test_auth.py
```

To run specific test functions:

```bash
pytest app/tests/integration/test_auth.py::test_login_success
```

## Test Coverage

We aim for high test coverage, particularly for:

1. **Security-Critical Paths**: Authentication, authorization, password management
2. **Error Handling**: Verify proper error responses for invalid inputs
3. **Business Logic**: Ensure core business rules are enforced

## CI/CD Integration

Tests are automatically run in the CI/CD pipeline:

1. On every pull request
2. Before deployment to staging
3. As a gate for production deployment 