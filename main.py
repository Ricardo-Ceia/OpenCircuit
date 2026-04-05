"""Application entrypoint kept at repository root."""

from app.runtime.main import main as runtime_main


def main() -> None:
    runtime_main()


if __name__ == "__main__":
    main()
