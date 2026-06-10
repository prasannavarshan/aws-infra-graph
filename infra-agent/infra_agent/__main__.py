"""Application entry point — ``python -m infra_agent``."""

import uvicorn

from infra_agent.app import create_app
from infra_agent.config import Settings
from infra_agent.logging_config import setup_logging


def main() -> None:
    """Load settings, configure logging, and start the uvicorn server."""
    settings = Settings()
    setup_logging(settings.LOG_LEVEL)

    app = create_app(settings)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    main()
