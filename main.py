"""Application entrypoint kept at repository root."""

import importlib.util
import pathlib
import sys


def _load_runtime_main():
    runtime_main = pathlib.Path(__file__).parent / "app" / "runtime" / "main.py"
    spec = importlib.util.spec_from_file_location("app.runtime.main", runtime_main)
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load app.runtime.main")
    module = importlib.util.module_from_spec(spec)
    sys.modules["app.runtime.main"] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    module = _load_runtime_main()
    module.main()


if __name__ == "__main__":
    main()
