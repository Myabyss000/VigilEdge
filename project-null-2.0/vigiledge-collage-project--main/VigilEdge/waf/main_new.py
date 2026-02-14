"""
VigilEdge WAF - Main Application Entry Point
A slim entry point that imports and runs the application from app.py.
"""

import uvicorn
from app import app
from vigiledge.config import get_settings

settings = get_settings()


def main():
    """Main application entry point."""
    uvicorn.run(
        "app:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        access_log=True,
        log_level=settings.log_level.lower()
    )


if __name__ == "__main__":
    main()
