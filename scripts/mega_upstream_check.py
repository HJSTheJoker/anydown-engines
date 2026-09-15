#!/usr/bin/env python3
"""Write an upstream upgrade proposal without modifying the maintained fork."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    latest = json.loads(
        subprocess.check_output(["gh", "api", "repos/tonikelope/megabasterd/releases/latest"])
    )
    pin = json.loads((repository / "upstream.lock.json").read_text())
    if latest["tag_name"].lstrip("v") == pin["version"].lstrip("v"):
        print("Upstream release is unchanged")
        return
    # A proposal is deliberately separate from the qualified engine pin.
    (repository / "UPSTREAM_UPDATE.json").write_text(
        json.dumps(
            {
                "current_commit": pin["commit"],
                "current_version": pin["version"],
                "proposed_tag": latest["tag_name"],
                "release_url": latest["html_url"],
                "published_at": latest["published_at"],
                "qualification_required": [
                    "headless protocol",
                    "download integrity and resume",
                    "account and upload fixtures",
                    "stream range and seeking",
                    "all supported platform packages",
                    "migration and rollback",
                ],
            },
            indent=2,
        )
        + "\n"
    )
    print("Prepared upstream upgrade proposal for review")


if __name__ == "__main__":
    main()
