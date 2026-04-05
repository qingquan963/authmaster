# AuthMaster Python SDK

Official Python SDK for the AuthMaster authentication and authorization API.

## Installation

```bash
pip install authmaster
```

For async support:
```bash
pip install authmaster[async]
```

## Quick Start

```python
from authmaster import AuthMasterClient

# Initialize client with your API credentials
client = AuthMasterClient(
    api_key="ak_xxxxxxxxxxxx",
    api_secret="your_api_secret",
    base_url="https://auth.example.com/api/v1",
)

# Login
result = client.login(
    username="user@example.com",
    password="password123",
)
print(result["access_token"])

# List users
users = client.list_users(page=1, page_size=20)
for user in users["items"]:
    print(user["email"])

# Create a user
user = client.create_user(
    username="john_doe",
    email="john@example.com",
    password="SecurePass123!",
    idempotency_key="create_user:john_doe",
)

# Get quota
quota = client.get_quota()
print(f"Used: {quota['monthly_used']} / {quota['monthly_quota']}")

# Logout
client.logout(revoke_all=True)
```

## Async Usage

```python
import asyncio
from authmaster import AuthMasterAsyncClient

async def main():
    async with AuthMasterAsyncClient(
        api_key="ak_xxxxx",
        api_secret="your_secret",
    ) as client:
        result = await client.login("user@example.com", "password")
        print(result["access_token"])

asyncio.run(main())
```

## Features

- **HMAC-SHA256 request signing** — All requests are cryptographically signed
- **Automatic token refresh** — Expired access tokens are automatically refreshed
- **Automatic retry** — Transient errors (rate limit, server errors) are automatically retried with exponential backoff
- **Idempotency keys** — Safe retry support for POST requests to prevent duplicates
- **Type-safe errors** — All error codes map to specific exception classes

## Error Handling

```python
from authmaster import (
    AuthMasterClient,
    InvalidCredentialsError,
    MFARequiredError,
    RateLimitError,
    PermissionDeniedError,
)

client = AuthMasterClient(api_key="ak_xxx", api_secret="secret")

try:
    result = client.login("user@example.com", "wrong_password")
except InvalidCredentialsError:
    print("Wrong username or password")
except MFARequiredError as e:
    print(f"MFA required: {e.details}")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds")
```

## API Reference

### Authentication

- `client.login(username, password, **kwargs)` — Login with credentials
- `client.login_with_mfa(mfa_token, code, code_type)` — Complete MFA login
- `client.logout(session_id=None, revoke_all=False)` — Logout
- `client.refresh()` — Refresh access token
- `client.get_session()` — Get current session info

### Users

- `client.list_users(page=1, page_size=20)` — List users with pagination
- `client.create_user(username, email, password, **kwargs)` — Create user
- `client.get_user(user_id)` — Get user by ID
- `client.update_user(user_id, **kwargs)` — Update user fields
- `client.delete_user(user_id)` — Soft-delete a user

### Roles

- `client.list_roles()` — List all roles
- `client.create_role(name, description, permissions)` — Create role
- `client.assign_permission(role_id, permission)` — Assign permission
- `client.remove_permission(role_id, permission)` — Remove permission

### Quota

- `client.get_quota()` — Get current quota and rate limits
- `client.get_quota_usage(period="daily")` — Get detailed usage

## License

MIT License
