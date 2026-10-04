"""Load tracked programs sent to a server for one remote operation."""

from pathlib import Path


def load_remote_source(
    filename: str,
    *,
    source_kind: str,
    exception_type: type[Exception],
) -> str:
    """Read one tracked remote program and translate local file errors."""
    try:
        return (Path(__file__).with_name("remote_sources") / filename).read_text(encoding="utf-8")
    except OSError as error:
        raise exception_type(f"Could not read remote {source_kind} source {filename}.") from error
