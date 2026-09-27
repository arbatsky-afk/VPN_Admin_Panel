"""Local adapter for the canonical server-bundle component declaration contract."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_CONTRACT_PATH = (
    Path(__file__).parents[2]
    / "scripts"
    / "ubuntu"
    / "modular-deployment"
    / "lib"
    / "component_declaration.py"
)
_MODULE_NAME = "vpn_admin_panel_component_declaration"
_specification = importlib.util.spec_from_file_location(_MODULE_NAME, _CONTRACT_PATH)
if _specification is None or _specification.loader is None:
    raise RuntimeError("Could not load the component declaration contract.")
_contract = importlib.util.module_from_spec(_specification)
sys.modules.setdefault(_MODULE_NAME, _contract)
_specification.loader.exec_module(_contract)

DeclarationError = _contract.DeclarationError
COMPONENT_ID_PATTERN = _contract.COMPONENT_ID
HEALTH_CHECKS_BY_COMPONENT = _contract.HEALTH_CHECKS_BY_COMPONENT
MANAGEMENT_ACTIONS_BY_HANDLER = _contract.MANAGEMENT_ACTIONS_BY_HANDLER
REMOTE_PATH_PATTERN = _contract.REMOTE_PATH
RESTORE_ACTIONS = _contract.RESTORE_ACTIONS
SCHEMA_VERSION = _contract.SCHEMA_VERSION
SYSTEMD_UNIT_PATTERN = _contract.SYSTEMD_UNIT
validate_declaration_data = _contract.validate_declaration_data
validate_declaration_text = _contract.validate_declaration_text


def contract_source() -> str:
    """Return import-free validator definitions for the one-shot Inventory program."""
    try:
        return _CONTRACT_PATH.read_text(encoding="utf-8").replace(
            "from __future__ import annotations\n",
            "",
        )
    except OSError as error:
        raise RuntimeError("Could not read the component declaration contract.") from error
