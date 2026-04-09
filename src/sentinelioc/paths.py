from __future__ import annotations

import os
import platform
from pathlib import Path


def get_startup_paths() -> list[Path]:
    system = platform.system().lower()
    home = Path.home()
    candidates: list[Path] = []

    if system == "windows":
        appdata = os.environ.get("APPDATA")
        program_data = os.environ.get("PROGRAMDATA")

        if appdata:
            candidates.append(
                Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            )
        if program_data:
            candidates.append(
                Path(program_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            )
    else:
        candidates.extend(
            [
                home / ".config" / "autostart",
                home / ".profile",
                home / ".bashrc",
            ]
        )

    return candidates
