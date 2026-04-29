import logging
import os
from flask import Flask, request
from .config import Config
from .db import init_db
from .routes import register_routes

def configure_logging(app: Flask) -> None:
    log_level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, log_level_name, logging.INFO)

    # Configure root logger (so that libraries like SQLAlchemy also log)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    # Flask's app.logger uses the "flask.app" logger under the hood.
    app.logger.setLevel(level)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Configure logging before anything else
    configure_logging(app)

    @app.before_request
    def log_request():
        app.logger.info("Incoming request %s %s", request.method, request.path)

    @app.after_request
    def log_response(response):
        app.logger.info(
            "Completed request %s %s with status %s",
            request.method,
            request.path,
            response.status_code,
        )
        return response

    init_db(app)
    register_routes(app)
    return app
