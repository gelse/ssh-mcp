# 04b - Harden Command Segmentation Against Injection

**Parent Plan**: [04-security.md](plans/04-security.md)

## Objective
Add detection for `$()`, backtick substitution, `&&`, `||`, and newline injection to the command segmenter in [`lib/auth.py`](lib/auth.py:1).

## Context
The current `_split_command_segments()` splits on `|&;` characters. It does not catch shell substitution (`$()`, backticks), chained operators (`&&`, `||`), or newline injection. These could bypass authorization checks.

## Implementation Steps
1. Update `_split_command_segments()` in `lib/auth.py`:
   - Add `&&` and `||` as segment delimiters
   - Add pre-check for `$(` and `` ` `` (backtick) in raw command — reject outright
   - Add pre-check for newline (`\n`) in command — reject
2. Add `_check_dangerous_patterns(command: str) -> list[str]` method
   - Returns list of dangerous substrings found
3. In `check_command()`, call `_check_dangerous_patterns()` before splitting
   - If dangerous patterns found, reject with specific reason
4. Add parametrized tests with injection payloads:
   - `$(whoami)`, `` `whoami` ``, `cmd1 && cmd2`, `cmd1 || cmd2`
   - `cmd1\ncmd2`, `cmd1; cmd2` (already handled but verify)
   - Unicode homoglyphs for pipe: `cmd1 ｜ cmd2` (fullwidth vertical bar)

## Dependencies
- None

## Acceptance Criteria
- `$()`, backtick, `&&`, `||`, and newline in commands are rejected
- Rejection includes clear reason in auth result
- Parametrized tests for at least 10 injection payloads
- Existing chained command tests (`;`) still pass
