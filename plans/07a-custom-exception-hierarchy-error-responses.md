# 07a - Implement Custom Exception Hierarchy & Typed Error Responses

**Parent Plan**: [07-error-handling-resilience.md](plans/07-error-handling-resilience.md)

## Objective
Replace broad `except Exception` catches and `ValueError` usage with custom exception types, and return structured error responses with error type, message, and retryable flag.

## Implementation Steps
1. Use exception hierarchy from `lib/exceptions.py` (created in task 02a)
2. Replace all `raise ValueError(...)` in [`server.py`](server.py:1) with appropriate custom exceptions:
   - Unknown target → `SSHConnectionError`
   - Sudo not allowed → `AuthorizationError`
   - Path traversal → `PathValidationError`
3. Replace `except Exception as e` in tool handlers with specific exception catches:
   - `except SSHAuthenticationError` → 401-like error
   - `except SSHTimeoutError` → timeout error with retryable=true
   - `except AuthorizationError` → forbidden error
   - `except MCPSSHError` → domain error with structured response
   - `except Exception` → 500 internal error (last resort)
4. Create error response helper `_format_error(exc: MCPSSHError) -> dict` that produces:
   ```json
   {"error": true, "error_type": "SSHTimeoutError", "message": "...", "retryable": true}
   ```
5. Add request ID to all error responses from request context
6. Update tests to expect new error format

## Dependencies
- Task 02a (exceptions module)

## Acceptance Criteria
- No bare `except Exception` in tool handlers (specific types caught)
- Error responses include `error_type`, `message`, `retryable` fields
- Built-in exceptions only used as last resort
- All tests updated to match new error format
