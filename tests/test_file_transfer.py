"""Unit tests for the FileTransferService class."""

import os
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import paramiko

from lib.exceptions import MCPSSHError
from lib.file_transfer import FileTransferService, FileTransferError


class TestValidatePath:
    """Tests for FileTransferService._validate_path()."""

    def setup_method(self):
        self.service = FileTransferService()

    def test_absolute_path_passes(self):
        """Absolute paths should pass validation."""
        result = self.service._validate_path("/home/user/file.txt")
        assert result == "/home/user/file.txt"

    def test_deep_path_passes(self):
        """Deep absolute paths should pass validation."""
        result = self.service._validate_path("/a/b/c/d/e/f/g.txt")
        assert result == "/a/b/c/d/e/f/g.txt"

    def test_root_path_passes(self):
        """Root-level file should pass validation."""
        result = self.service._validate_path("/file.txt")
        assert result == "/file.txt"

    def test_empty_path_raises(self):
        """Empty path should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="must not be empty"):
            self.service._validate_path("")

    def test_relative_path_raises(self):
        """Relative path should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="must be absolute"):
            self.service._validate_path("home/user/file.txt")

    def test_dot_only_path_raises(self):
        """'.' path should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="component must not be"):
            self.service._validate_path(".")

    def test_parent_directory_traversal_raises(self):
        """Path with '..' should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="component must not be"):
            self.service._validate_path("/home/../etc/passwd")

    def test_double_dot_at_end_raises(self):
        """Path ending with '/..' should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="component must not be"):
            self.service._validate_path("/home/user/..")

    def test_null_byte_raises(self):
        """Path containing null byte should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="null byte"):
            self.service._validate_path("/home/\x00file.txt")

    def test_null_byte_mid_path_raises(self):
        """Path with null byte in the middle should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="null byte"):
            self.service._validate_path("/etc/passw\x00d")

    def test_normal_dots_dont_trigger_traversal(self):
        """Single dots (current dir) should not trigger traversal check."""
        # "." is a single dot — not ".." — so it should not be rejected
        # by the traversal check (but will be rejected as non-absolute)
        # Test with absolute path containing single dot file
        result = self.service._validate_path("/home/user/my.file.txt")
        assert result == "/home/user/my.file.txt"


class TestDownloadFile:
    """Tests for FileTransferService.download_file()."""

    def setup_method(self):
        self.service = FileTransferService()
        self.ssh_client = MagicMock(spec=paramiko.SSHClient)

    def test_download_returns_filename_and_content(self):
        """download_file should return (filename, bytes)."""
        sftp = MagicMock()
        mock_stat = MagicMock()
        mock_stat.st_size = 100
        sftp.stat.return_value = mock_stat

        mock_file = MagicMock()
        mock_file.__enter__.return_value.read.return_value = b"hello world"
        sftp.file.return_value = mock_file

        self.ssh_client.open_sftp.return_value = sftp

        filename, content = self.service.download_file(
            self.ssh_client, "/tmp/data.bin"
        )

        assert filename == "data.bin"
        assert content == b"hello world"

    def test_download_validates_path_first(self):
        """download_file should validate path before opening SFTP."""
        self.ssh_client.open_sftp = MagicMock()

        with pytest.raises(FileTransferError, match="must be absolute"):
            self.service.download_file(self.ssh_client, "relative/path")

        self.ssh_client.open_sftp.assert_not_called()

    def test_download_rejects_oversized_file(self):
        """download_file should reject files exceeding size limit."""
        sftp = MagicMock()
        mock_stat = MagicMock()
        mock_stat.st_size = 20 * 1024 * 1024  # 20 MB > 10 MB limit
        sftp.stat.return_value = mock_stat
        self.ssh_client.open_sftp.return_value = sftp

        with pytest.raises(FileTransferError, match="exceeds limit"):
            self.service.download_file(self.ssh_client, "/tmp/bigfile.bin")

    def test_download_closes_sftp_on_error(self):
        """SFTP session should be closed even when an error occurs."""
        sftp = MagicMock()
        sftp.stat.side_effect = IOError("simulated error")
        self.ssh_client.open_sftp.return_value = sftp

        with pytest.raises(IOError, match="simulated error"):
            self.service.download_file(self.ssh_client, "/tmp/test.bin")

        sftp.close.assert_called_once()

    def test_download_closes_sftp_on_success(self):
        """SFTP session should be closed on successful download."""
        sftp = MagicMock()
        mock_stat = MagicMock()
        mock_stat.st_size = 10
        sftp.stat.return_value = mock_stat

        mock_file = MagicMock()
        mock_file.__enter__.return_value.read.return_value = b"test"
        sftp.file.return_value = mock_file

        self.ssh_client.open_sftp.return_value = sftp

        self.service.download_file(self.ssh_client, "/tmp/test.txt")
        sftp.close.assert_called_once()

    def test_download_respects_custom_size_limit(self):
        """download_file should respect custom max_file_size_bytes."""
        service = FileTransferService(max_file_size_bytes=100)

        sftp = MagicMock()
        mock_stat = MagicMock()
        mock_stat.st_size = 50
        sftp.stat.return_value = mock_stat

        mock_file = MagicMock()
        mock_file.__enter__.return_value.read.return_value = b"x" * 50
        sftp.file.return_value = mock_file

        self.ssh_client.open_sftp.return_value = sftp

        # Should pass with 50-byte file under 100-byte limit
        filename, content = service.download_file(self.ssh_client, "/tmp/small.txt")
        assert content == b"x" * 50

        # Should reject a 200-byte file over 100-byte limit
        sftp.stat.return_value.st_size = 200
        with pytest.raises(FileTransferError, match="exceeds limit"):
            service.download_file(self.ssh_client, "/tmp/big.txt")

    def test_download_null_byte_in_path_raises(self):
        """Null byte in path should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="null byte"):
            self.service.download_file(self.ssh_client, "/tmp/\x00bad.txt")

    def test_download_parent_traversal_raises(self):
        """Parent dir traversal in path should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="component must not be"):
            self.service.download_file(self.ssh_client, "/tmp/../etc/passwd")


class TestUploadFile:
    """Tests for FileTransferService.upload_file()."""

    def setup_method(self):
        self.service = FileTransferService()
        self.ssh_client = MagicMock(spec=paramiko.SSHClient)

    def test_upload_writes_content(self):
        """upload_file should write bytes to the remote file."""
        sftp = MagicMock()
        mock_file = MagicMock()
        sftp.file.return_value = mock_file
        self.ssh_client.open_sftp.return_value = sftp

        self.service.upload_file(self.ssh_client, "/tmp/upload.txt", b"hello")

        mock_file.__enter__.return_value.write.assert_called_once_with(b"hello")

    def test_upload_validates_path_first(self):
        """upload_file should validate path before opening SFTP."""
        self.ssh_client.open_sftp = MagicMock()

        with pytest.raises(FileTransferError, match="must be absolute"):
            self.service.upload_file(self.ssh_client, "relative.txt", b"data")

        self.ssh_client.open_sftp.assert_not_called()

    def test_upload_rejects_oversized_content(self):
        """upload_file should reject content exceeding size limit."""
        with pytest.raises(FileTransferError, match="exceeds limit"):
            self.service.upload_file(
                self.ssh_client, "/tmp/big.txt", b"x" * (11 * 1024 * 1024)
            )

    def test_upload_closes_sftp_on_error(self):
        """SFTP session should be closed when write fails."""
        sftp = MagicMock()
        sftp.file.side_effect = IOError("simulated write error")
        self.ssh_client.open_sftp.return_value = sftp

        with pytest.raises(IOError, match="simulated write error"):
            self.service.upload_file(self.ssh_client, "/tmp/test.bin", b"data")

        sftp.close.assert_called_once()

    def test_upload_closes_sftp_on_success(self):
        """SFTP session should be closed after successful upload."""
        sftp = MagicMock()
        mock_file = MagicMock()
        sftp.file.return_value = mock_file
        self.ssh_client.open_sftp.return_value = sftp

        self.service.upload_file(self.ssh_client, "/tmp/ok.txt", b"data")
        sftp.close.assert_called_once()

    def test_upload_respects_custom_size_limit(self):
        """upload_file should respect custom max_file_size_bytes."""
        service = FileTransferService(max_file_size_bytes=500)

        # Under limit should pass
        sftp = MagicMock()
        mock_file = MagicMock()
        sftp.file.return_value = mock_file
        self.ssh_client.open_sftp.return_value = sftp

        service.upload_file(self.ssh_client, "/tmp/small.txt", b"x" * 400)
        # Should have been called
        assert sftp.file.called

        # Over limit should reject
        with pytest.raises(FileTransferError, match="exceeds limit"):
            service.upload_file(self.ssh_client, "/tmp/big.txt", b"x" * 600)

    def test_upload_null_byte_in_path_raises(self):
        """Null byte in path should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="null byte"):
            self.service.upload_file(self.ssh_client, "/tmp/\x00bad.txt", b"data")

    def test_upload_parent_traversal_raises(self):
        """Parent dir traversal in path should raise FileTransferError."""
        with pytest.raises(FileTransferError, match="component must not be"):
            self.service.upload_file(
                self.ssh_client, "/tmp/../etc/passwd", b"data"
            )


class TestFileTransferError:
    """Tests for the FileTransferError exception class."""

    def test_is_exception_subclass(self):
        """FileTransferError should be a subclass of MCPSSHError and Exception."""
        assert issubclass(FileTransferError, MCPSSHError)
        assert issubclass(FileTransferError, Exception)

    def test_can_be_raised_and_caught(self):
        """FileTransferError should behave as a normal exception."""
        with pytest.raises(FileTransferError, match="test message"):
            raise FileTransferError("test message")

    def test_str_representation(self):
        """FileTransferError string representation should include message."""
        error = FileTransferError("something went wrong")
        assert str(error) == "something went wrong"


# =============================================================================
# Hardened Path Validation — Traversal & Encoding Attacks (Task 04c)
# =============================================================================


class TestHardenValidatePath:
    """Hardened _validate_path() tests for traversal and encoding attacks."""

    def setup_method(self):
        self.service = FileTransferService()

    # ------------------------------------------------------------------
    # Valid paths (regression)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("path", [
        "/subdir/file.txt",
        "/a/b/c/d.txt",
        "/home/user/my.file.txt",
        "/tmp/data.log",
        "/var/log/app/access.log",
    ])
    def test_valid_paths_pass(self, path):
        """Valid absolute paths should pass hardened validation."""
        result = self.service._validate_path(path)
        assert result == os.path.normpath(path)

    # ------------------------------------------------------------------
    # URL-encoded traversal (double-encoding)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("path,description", [
        ("/%2e%2e%2fetc%2fpasswd", "%2e%2e%2f → ../"),
        ("/%2e%2e/etc/passwd", "%2e%2e/ → ../"),
        ("/%2E%2E%2Fetc%2Fpasswd", "uppercase %2E%2E%2F"),
        ("/foo/%2e%2e%2fbar/../etc/passwd", "mixed encoded + literal"),
        ("/%2e%2e%2f", "trailing encoded traversal"),
    ])
    def test_double_encoded_traversal_rejected(self, path, description):
        """Double-encoded traversal sequences must be rejected."""
        with pytest.raises(FileTransferError, match="percent-encoded"):
            self.service._validate_path(path)

    def test_percent_encoded_null_byte_rejected(self):
        """Percent-encoded null byte (%00) must be rejected via decoded check."""
        with pytest.raises(FileTransferError, match="percent-encoded"):
            self.service._validate_path("/tmp/file%00.txt")

    # ------------------------------------------------------------------
    # Unicode homoglyph traversal
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("path,description", [
        ("/\u2215etc\u2215passwd", "division slash as /"),
        ("/..\u2215etc\u2215passwd", ".. followed by division slash"),
        ("/\u2024\u2024/etc/passwd", "two-dot-leader as .."),
        ("/\u2025/etc/passwd", "two-dot-leader (single char) as .."),
    ])
    def test_unicode_traversal_rejected(self, path, description):
        """Unicode homoglyph path traversal must be rejected."""
        with pytest.raises(FileTransferError, match="dangerous Unicode"):
            self.service._validate_path(path)

    # ------------------------------------------------------------------
    # Tilde prefix in components
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("path,description", [
        ("/~root/.ssh/id_rsa", "tilde-prefixed component ('~root')"),
        ("/home/user/~backup/data.txt", "tilde in middle component"),
        ("/~/.config/app.conf", "tilde-only component"),
    ])
    def test_tilde_component_rejected(self, path, description):
        """Path components starting with '~' must be rejected."""
        with pytest.raises(FileTransferError, match="must not start with '~'"):
            self.service._validate_path(path)

    # ------------------------------------------------------------------
    # Mixed null byte + traversal
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("path,description", [
        ("/legit\x00../etc/passwd", "null byte before traversal"),
        ("/home/\x00../etc/shadow", "null byte mid-path with .."),
    ])
    def test_null_byte_with_traversal_rejected(self, path, description):
        """Null byte combined with traversal must be rejected (null caught first)."""
        with pytest.raises(FileTransferError, match="null byte"):
            self.service._validate_path(path)

    # ------------------------------------------------------------------
    # Deep nesting traversal
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("path,description", [
        ("/foo/bar/../../../etc/passwd", "triple parent traversal"),
        ("/a/b/c/d/e/f/g/../../../../../../etc/hosts", "deep traversal"),
        ("/deep/path/here/../../secret/file", "intermediate traversal"),
    ])
    def test_deep_nesting_traversal_rejected(self, path, description):
        """Deeply nested parent directory traversal must be rejected."""
        with pytest.raises(FileTransferError, match="component must not be"):
            self.service._validate_path(path)

    # ------------------------------------------------------------------
    # Symlink escape (via realpath mocking)
    # ------------------------------------------------------------------

    def test_symlink_escape_resolved_by_realpath(self):
        """Paths resolved via symlinks outside sandbox must be rejected."""
        # Simulate: /allowed/sftp/root/legit.txt is a symlink → /etc/passwd
        sandbox = "/allowed/sftp/root"
        service = FileTransferService(sandbox_root=sandbox)

        with patch("os.path.realpath") as mock_realpath:
            # normpath produces: /allowed/sftp/root/legit.txt
            # realpath resolves the symlink: /etc/passwd
            mock_realpath.side_effect = lambda p: (
                "/etc/passwd"
                if p == "/allowed/sftp/root/legit.txt"
                else os.path.realpath(p)
            )

            with pytest.raises(FileTransferError, match="outside the allowed sandbox"):
                service._validate_path("/allowed/sftp/root/legit.txt")

    def test_symlink_within_sandbox_allowed(self):
        """Symlinks that resolve inside the sandbox must be allowed."""
        sandbox = "/allowed/sftp/root"
        service = FileTransferService(sandbox_root=sandbox)

        with patch("os.path.realpath") as mock_realpath:
            mock_realpath.side_effect = lambda p: (
                "/allowed/sftp/root/data/subdir/file.txt"
                if p == os.path.normpath("/allowed/sftp/root/link.txt")
                else os.path.realpath(p)
            )

            result = service._validate_path("/allowed/sftp/root/link.txt")
            assert result == os.path.normpath("/allowed/sftp/root/link.txt")

    # ------------------------------------------------------------------
    # Sandbox root enforcement
    # ------------------------------------------------------------------

    def test_path_inside_sandbox_allowed(self):
        """Path within the configured sandbox root must be allowed."""
        service = FileTransferService(sandbox_root="/home/app/sftp")
        result = service._validate_path("/home/app/sftp/data.txt")
        assert result == "/home/app/sftp/data.txt"

    def test_path_outside_sandbox_rejected(self):
        """Path outside the configured sandbox root must be rejected."""
        service = FileTransferService(sandbox_root="/home/app/sftp")
        with pytest.raises(FileTransferError, match="outside the allowed sandbox"):
            service._validate_path("/etc/passwd")

    def test_default_sandbox_is_root(self):
        """Default sandbox root '/' allows full filesystem access."""
        service = FileTransferService()
        result = service._validate_path("/etc/passwd")
        assert result == "/etc/passwd"

    def test_adjacent_sandbox_name_not_confused(self):
        """Path like '/etcX/passwd' must not pass when sandbox is '/etc'."""
        service = FileTransferService(sandbox_root="/etc")
        with pytest.raises(FileTransferError, match="outside the allowed sandbox"):
            service._validate_path("/etcX/passwd")

    # ------------------------------------------------------------------
    # Empty component (double-slash) normalization
    # ------------------------------------------------------------------

    def test_double_slash_normalized(self):
        """Double slashes (//) must be normalized by normpath."""
        result = self.service._validate_path("/tmp//file.txt")
        assert result == "/tmp/file.txt"
