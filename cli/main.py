import sys

from .config import load_config
from .parser import build_parser


def main() -> None:
    config = load_config(create_if_missing=False)
    parser = build_parser(config)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
