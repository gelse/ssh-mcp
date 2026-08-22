"""Minimal paramiko stub for the config-api Docker image.

The config-api only needs ``lib.config``, ``lib.constants``, and
``lib.exceptions`` at runtime, but ``lib/__init__.py`` eagerly imports
``lib.file_transfer`` and ``lib.ssh_client`` which both ``import paramiko``.
This stub provides just enough symbols for those modules to import
successfully without the full paramiko library.
"""


class _Stub:
    """Placeholder class for paramiko types not used by the config API."""

    def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
        pass


SSHClient = _Stub
Ed25519Key = _Stub
RSAKey = _Stub
AutoAddPolicy = _Stub
SFTPClient = _Stub
