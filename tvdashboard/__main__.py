"""Entry point: `python -m tvdashboard`.

Configuration comes from the environment only (design.md §11). There are no command-line
options, because there is no configuration this appliance takes that a container cannot set.
"""

from __future__ import annotations

import sys

from .config import Config
from .web import serve


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if args and args[0] in {"-h", "--help", "help"}:
        sys.stdout.write(_USAGE)
        return 0
    if args and args[0] in {"-V", "--version", "version"}:
        from . import __version__

        sys.stdout.write(f"tvdashboard {__version__}\n")
        return 0
    if args:
        sys.stderr.write(f"tvdashboard: unexpected argument {args[0]!r}\n{_USAGE}")
        return 2
    return serve(Config.from_env())


_USAGE = """usage: python -m tvdashboard

Browser dashboard for one Android TV over wireless adb. Configured by environment only:

  TVD_DATA_DIR             state directory                       [default /data]
  TVD_HTTP_ADDR            listen address                        [default 0.0.0.0:8080]
  TVD_ALLOW_INSECURE_HTTP  1 = plain HTTP without a warning
  TVD_ALLOWED_CIDRS        comma-separated discovery scope       [default RFC1918]
  TVD_DEVICE_PORTS         comma-separated adb ports             [default 5555,5556,5557]
  TVD_ADB_BIN              adb binary                            [default adb]

See docs/design.md §11 for the full table.
"""


if __name__ == "__main__":
    raise SystemExit(main())
