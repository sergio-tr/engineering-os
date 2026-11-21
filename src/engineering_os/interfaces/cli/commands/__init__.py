"""CLI command registration helpers."""

from __future__ import annotations

import argparse
from typing import Callable, List

Registrar = Callable[[argparse._SubParsersAction], None]


def register_all(sub: argparse._SubParsersAction, registrars: List[Registrar]) -> None:
    for register in registrars:
        register(sub)
