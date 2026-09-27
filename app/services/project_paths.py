"""Resolution of project-managed paths from local configuration."""

from pathlib import Path

_PANEL_SETTINGS_RELATIVE_PATH = "runtime/panel/settings.json"


def resolve_project_relative_path(project_directory: Path, configured_path: str) -> Path:
    """Resolve a relative project path and reject paths outside the project root."""
    path = Path(configured_path)
    if path.is_absolute():
        raise ValueError("Project-managed paths must be relative to the project directory.")

    project_root = project_directory.resolve()
    resolved_path = (project_root / path).resolve()
    try:
        resolved_path.relative_to(project_root)
    except ValueError as error:
        raise ValueError(
            "Project-managed paths must stay inside the project directory."
        ) from error
    return resolved_path


def panel_settings_path(project_directory: Path) -> Path:
    """Return the project-managed path to the VPN Admin Panel settings file."""
    return resolve_project_relative_path(
        project_directory,
        _PANEL_SETTINGS_RELATIVE_PATH,
    )
