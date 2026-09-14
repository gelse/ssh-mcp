"""Tests for the hand-written ``config.schema.json`` JSON Schema.

These tests validate the *structure* of the schema file without pulling in the
``jsonschema`` runtime dependency.  They assert that the schema is well-formed
JSON and mirrors the strict validation performed by
:meth:`lib.config.ConfigManager._validate`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lib.constants import SETTING_KEY_TYPES

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "config.schema.json"
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "default-config.json"

# The top-level keys the schema lists as required (mirrors _validate, which
# tolerates a missing block_patterns by defaulting to an empty list).
EXPECTED_REQUIRED_KEYS = {
    "version",
    "ssh_targets",
    "allowed_commands",
    "settings",
}

# The settings keys validated by ConfigManager._validate, derived from the
# SETTING_KEY_TYPES mapping so the schema test stays in sync with _validate.
EXPECTED_SETTING_KEYS = set(SETTING_KEY_TYPES.keys()) | {"sftp", "rate_limit"}


def _load_schema() -> dict:
    """Load and decode the hand-written schema as JSON."""
    with SCHEMA_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


class TestSchemaStructure:
    """Structural integrity of config.schema.json."""

    def test_schema_is_valid_json(self) -> None:
        """The schema file parses as JSON without error."""
        assert isinstance(_load_schema(), dict)

    def test_draft_2020_12_declared(self) -> None:
        """The schema declares the Draft 2020-12 dialect."""
        schema = _load_schema()
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"

    def test_root_is_non_additional_object(self) -> None:
        """The root is an object that does not allow unknown keys."""
        schema = _load_schema()
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False

    def test_required_keys_present(self) -> None:
        """All top-level keys enforced by _validate are declared as required."""
        schema = _load_schema()
        assert set(schema["required"]) == EXPECTED_REQUIRED_KEYS

    def test_version_is_const_one(self) -> None:
        """Only config schema version 1 is accepted."""
        schema = _load_schema()
        assert schema["properties"]["version"]["const"] == 1

    def test_ssh_targets_min_properties(self) -> None:
        """ssh_targets must be a non-empty object."""
        schema = _load_schema()
        targets = schema["properties"]["ssh_targets"]
        assert targets["type"] == "object"
        assert targets["minProperties"] == 1

    def test_schema_property_declared(self) -> None:
        """The root properties include ``$schema`` as a string type."""
        schema = _load_schema()
        assert "$schema" in schema["properties"]
        assert schema["properties"]["$schema"]["type"] == "string"


class TestSettingsSchema:
    """The settings section mirrors the 13 validated keys."""

    def test_all_setting_keys_represented(self) -> None:
        """Every setting key validated at load time appears in the schema."""
        schema = _load_schema()
        settings_props = schema["$defs"]["settings"]["properties"]
        assert set(settings_props.keys()) == EXPECTED_SETTING_KEYS


class TestRuleSudoAllowedSchema:
    """The ``rule`` $defs block declares the ``sudo_allowed`` property."""

    def test_rule_defines_sudo_allowed(self) -> None:
        """The rule definition contains the sudo_allowed array property."""
        schema = _load_schema()
        rule_props = schema["$defs"]["rule"]["properties"]
        assert "sudo_allowed" in rule_props
        sudo_allowed = rule_props["sudo_allowed"]
        assert sudo_allowed["type"] == "array"
        assert sudo_allowed["items"]["type"] == "string"
        assert sudo_allowed["items"]["minLength"] == 1

    def test_rule_required_unchanged(self) -> None:
        """sudo_allowed is optional: required still lists only two keys."""
        schema = _load_schema()
        rule = schema["$defs"]["rule"]
        assert set(rule["required"]) == {"targets", "commands"}

    def test_rule_rejects_unknown_keys(self) -> None:
        """The rule definition keeps additionalProperties: false."""
        schema = _load_schema()
        assert schema["$defs"]["rule"]["additionalProperties"] is False


class TestRuleSudoAllowedValidation:
    """Instance validation of sudo_allowed against the bundled schema."""

    @staticmethod
    def _minimal_config_dict() -> dict:
        """Return a minimal config dict valid under the schema."""
        return {
            "version": 1,
            "ssh_targets": {
                "testbox": {
                    "host": "10.0.0.1",
                    "username": "admin",
                    "password": "secret",
                }
            },
            "allowed_commands": {
                "default": [
                    {
                        "targets": ["*"],
                        "commands": ["hostname"],
                        "sudo_allowed": ["hostname"],
                    }
                ],
                "api_keys": [],
                "networks": [],
            },
            "settings": {
                "max_output_length": 50000,
                "command_timeout_max": 120,
            },
        }

    def _validate(self, config: dict) -> None:
        """Validate *config* against the bundled schema, skipping cleanly."""
        jsonschema = pytest.importorskip("jsonschema")
        schema = _load_schema()
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(config)

    def test_valid_sudo_allowed_passes(self) -> None:
        """A config with valid sudo_allowed passes schema validation."""
        self._validate(self._minimal_config_dict())

    def test_absent_sudo_allowed_passes(self) -> None:
        """A rule without sudo_allowed remains valid (optional key)."""
        config = self._minimal_config_dict()
        del config["allowed_commands"]["default"][0]["sudo_allowed"]
        self._validate(config)

    def test_integer_sudo_allowed_entries_fail(self) -> None:
        """Integer sudo_allowed entries fail schema validation."""
        jsonschema = pytest.importorskip("jsonschema")
        config = self._minimal_config_dict()
        config["allowed_commands"]["default"][0]["sudo_allowed"] = [42]
        with pytest.raises(jsonschema.ValidationError):
            self._validate(config)

    def test_unknown_key_with_sudo_allowed_shape_fails(self) -> None:
        """An unknown sibling key alongside sudo_allowed is rejected."""
        jsonschema = pytest.importorskip("jsonschema")
        config = self._minimal_config_dict()
        config["allowed_commands"]["default"][0]["sudo_not_allowed"] = ["x"]
        with pytest.raises(jsonschema.ValidationError):
            self._validate(config)


class TestReferencesDefaultConfig:
    """The bundled default config points at the bundled schema."""

    def test_default_config_declares_schema_ref(self) -> None:
        """default-config.json carries the ``$schema`` reference."""
        with DEFAULT_CONFIG_PATH.open(encoding="utf-8") as fh:
            default_config = json.load(fh)
        assert default_config.get("$schema") == "./config.schema.json"

    def test_default_config_passes_draft_2020_12(self) -> None:
        """default-config.json validates against the schema."""
        jsonschema = pytest.importorskip("jsonschema")
        schema = _load_schema()
        with DEFAULT_CONFIG_PATH.open(encoding="utf-8") as fh:
            default_config = json.load(fh)
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(default_config)
