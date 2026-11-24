"""Load the plugin (repo root) as the package `hermes_consent_network` without installing anything."""
import importlib
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(os.path.realpath(__file__)).parents[1]
PKG = "hermes_consent_network"


def load():
    if PKG in sys.modules:
        return sys.modules[PKG], sys.modules[PKG + ".core"], sys.modules[PKG + ".cli"]
    spec = importlib.util.spec_from_file_location(PKG, str(ROOT / "__init__.py"),
                                                  submodule_search_locations=[str(ROOT)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[PKG] = mod
    spec.loader.exec_module(mod)
    cli = importlib.import_module(PKG + ".cli")
    return mod, sys.modules[PKG + ".core"], cli
