"""SFTP file transfer service for upload and download operations."""

import os
import re
import urllib.parse
from typing import Optional, Tuple

import paramiko

from lib.constants import (
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DEFAULT_SFTP_SANDBOX_ROOT,
    DANGEROUS_UNICODE_PATH_CHARS,
)
from lib.exceptions import FileTransferError


# ---------------------------------------------------------------------------
# Compiled regex patterns for path-traversal detection
# ---------------------------------------------------------------------------

# Match percent-encoded dots/slashes used to bypass basic `..` filters.
# Examples: %2e%2e%2f → ../, %2e%2e/ → ../
_URL_ENCODED_TRAVERSAL_RE = re.compile(
    r"%[0-9a-fA-F]{2}",
)

# Match any character from the dangerous Unicode set.
_DANGEROUS_UNICODE_RE = re.compile(
    "[" + re.escape(DANGEROUS_UNICODE_PATH_CHARS) + "]",
)


class FileTransferService:
    """Handles SFTP file upload and download operations.

    Consolidates path validation and SFTP operations that were previously
    duplicated in ssh_download_file and ssh_upload_file tool handlers.
    """

    MAX_FILE_SIZE_BYTES: int = DEFAULT_MAX_FILE_SIZE_BYTES

    def __init__(
        self,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
        sandbox_root: str = DEFAULT_SFTP_SANDBOX_ROOT,
    ):
        """Initialize the file transfer service.

        Args:
            max_file_size_bytes: Maximum file size for transfers (default 10 MiB).
            sandbox_root: Allowed root directory for SFTP paths.  Resolved
                with :func:`os.path.realpath` before enforcement.  Defaults
                to ``"/"`` (full access).
        """
        self.max_file_size_bytes = max_file_size_bytes
        # Resolve the sandbox root once so that symlinks in the sandbox
        # directory itself don't affect enforcement.
        self._sandbox_root = os.path.realpath(sandbox_root)

    # ------------------------------------------------------------------
    # Path validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _has_url_encoded_traversal(remote_path: str) -> bool:
        """Check whether *remote_path* contains percent-encoded traversal.

        Decoding each ``%XX`` sequence and checking for ``..`` catches
        double-encoded attacks such as ``%2e%2e%2f`` or ``%2e%2e/``,
        which would bypass a plain ``".." in path`` check.
        """
        # Quick rejection: if there are no percent signs, bail early.
        if "%" not in remote_path:
            return False

        try:
            decoded = urllib.parse.unquote(remote_path)
        except (ValueError, UnicodeDecodeError):
            # Malformed percent sequences → suspicious; reject.
            return True

        return ".." in decoded or "\x00" in decoded

    @staticmethod
    def _contains_dangerous_unicode(remote_path: str) -> bool:
        """Return ``True`` if *remote_path* contains dangerous Unicode chars."""
        return bool(_DANGEROUS_UNICODE_RE.search(remote_path))

    # ------------------------------------------------------------------
    # Core validation
    # ------------------------------------------------------------------

    def _validate_path(self, remote_path: str) -> str:
        """Validate and normalize a remote file path.

        Checks (in order):

        1. Path is not empty.
        2. Path does **not** contain null bytes.
        3. Path does **not** contain dangerous Unicode homoglyphs
           (e.g. ``\\u2215`` division slash used as ``/``).
        4. Percent-decoded form does **not** contain ``..`` or null bytes
           (catches double-encoding such as ``%2e%2e%2f``).
        5. Each raw path component is validated: no component may be
           exactly ``.``, ``..``, or start with ``~``.
        6. After :func:`os.path.normpath`, the result must be absolute
           (start with ``/``).
        7. The :func:`os.path.realpath`-resolved path must start with the
           configured sandbox root.

        Args:
            remote_path: The remote file path to validate.

        Returns:
            The validated, normalized path string (post-``normpath``).

        Raises:
            FileTransferError: If the path fails any validation check.
        """
        # --- 1. Non-empty ---
        if not remote_path:
            raise FileTransferError("Remote path must not be empty")

        # --- 2. Null bytes ---
        if "\x00" in remote_path:
            raise FileTransferError("Remote path contains null byte")

        # --- 3. Dangerous Unicode homoglyphs ---
        if self._contains_dangerous_unicode(remote_path):
            raise FileTransferError(
                "Remote path contains dangerous Unicode characters"
            )

        # --- 4. URL-encoded traversal ---
        if self._has_url_encoded_traversal(remote_path):
            raise FileTransferError(
                "Remote path contains percent-encoded traversal sequences"
            )

        # --- 5. Validate raw components (before normpath collapses them) ---
        for part in remote_path.split(os.sep):
            if part == "." or part == "..":
                raise FileTransferError(
                    f"Remote path component must not be '{part}'"
                )
            if part.startswith("~"):
                raise FileTransferError(
                    "Remote path component must not start with '~'"
                )

        # --- 6. Normalize (collapse // and ./) then verify absolute ---
        normalized = os.path.normpath(remote_path)

        if not os.path.isabs(normalized):
            raise FileTransferError(
                f"Remote path must be absolute: {remote_path}"
            )

        # --- 7. Resolve symlinks and enforce sandbox ---
        real_path = os.path.realpath(normalized)

        # Prefix check: the resolved real path must start with the sandbox
        # root.  Use os.path.commonpath for a proper path-prefix check that
        # won't pass e.g. "/etcX/passwd" when sandbox is "/etc".
        if os.path.commonpath([real_path, self._sandbox_root]) != self._sandbox_root:
            raise FileTransferError(
                f"Resolved path '{real_path}' is outside the allowed "
                f"sandbox '{self._sandbox_root}'"
            )

        return normalized

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def download_file(
        self, ssh_client: paramiko.SSHClient, remote_path: str
    ) -> Tuple[str, bytes]:
        """Download a file from the remote server via SFTP.

        Args:
            ssh_client: A connected paramiko SSHClient instance.
            remote_path: Absolute path to the file on the remote server.

        Returns:
            A tuple of (filename, file_content_bytes).

        Raises:
            FileTransferError: If path validation fails, file not found,
                               or file exceeds size limit.
            paramiko.SSHException: On SFTP/connection errors.
        """
        remote_path = self._validate_path(remote_path)

        sftp = ssh_client.open_sftp()
        try:
            # Check file size before downloading
            stat = sftp.stat(remote_path)
            file_size = stat.st_size
            if file_size is None:
                raise FileTransferError(f"Could not stat file: {remote_path}")
            elif file_size > self.max_file_size_bytes:
                raise FileTransferError(
                    f"File size ({file_size} bytes) exceeds limit "
                    f"({self.max_file_size_bytes} bytes)"
                )

            with sftp.file(remote_path, "rb") as f:
                content = f.read()
        finally:
            sftp.close()

        filename = os.path.basename(remote_path)
        return filename, content

    def upload_file(
        self, ssh_client: paramiko.SSHClient, remote_path: str, content: bytes
    ) -> None:
        """Upload a file to the remote server via SFTP.

        Args:
            ssh_client: A connected paramiko SSHClient instance.
            remote_path: Absolute destination path on the remote server.
            content: File content as bytes.

        Raises:
            FileTransferError: If path validation fails or content exceeds limit.
            paramiko.SSHException: On SFTP/connection errors.
        """
        remote_path = self._validate_path(remote_path)

        if len(content) > self.max_file_size_bytes:
            raise FileTransferError(
                f"Content size ({len(content)} bytes) exceeds limit "
                f"({self.max_file_size_bytes} bytes)"
            )

        sftp = ssh_client.open_sftp()
        try:
            with sftp.file(remote_path, "wb") as f:
                f.write(content)
        finally:
            sftp.close()
