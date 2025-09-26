#!/usr/bin/env python3
import asyncio
import logging
import signal
import sys
from typing import Optional

from src.utils.config import get_settings
from src.database.connection import DatabasePool
from src.bmp.server import BMPServer

# Configure logging
def setup_logging(level: str = "INFO"):
    """Configure application logging."""
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    # Suppress verbose asyncio logs
    logging.getLogger("asyncio").setLevel(logging.WARNING)


class BMPCollectorApp:
    """Main application class for BMP Collector."""

    def __init__(self):
        self.settings = get_settings()
        self.db_pool: Optional[DatabasePool] = None
        self.bmp_server: Optional[BMPServer] = None
        self.shutdown_event = asyncio.Event()

    async def setup(self):
        """Setup application components."""
        logging.info("Starting BMP Collector...")

        # Initialize database connection pool
        self.db_pool = DatabasePool(self.settings)
        await self.db_pool.connect()
        logging.info("Database connection established")

        # Initialize BMP server
        self.bmp_server = BMPServer(self.settings, self.db_pool)

    async def cleanup(self):
        """Cleanup application resources."""
        logging.info("Shutting down BMP Collector...")

        # Stop BMP server
        if self.bmp_server:
            await self.bmp_server.stop()

        # Close database connections
        if self.db_pool:
            await self.db_pool.disconnect()

        logging.info("Shutdown complete")

    async def run(self):
        """Run the application."""
        try:
            await self.setup()

            # Setup signal handlers
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(
                    sig, lambda: asyncio.create_task(self.shutdown())
                )

            # Start BMP server
            server_task = asyncio.create_task(self.bmp_server.start())

            # Wait for shutdown
            await self.shutdown_event.wait()

            # Cancel server task
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass

        except Exception as e:
            logging.error(f"Application error: {e}")
            raise
        finally:
            await self.cleanup()

    async def shutdown(self):
        """Signal shutdown."""
        logging.info("Shutdown signal received")
        self.shutdown_event.set()


async def main():
    """Main entry point."""
    app = BMPCollectorApp()
    await app.run()


if __name__ == "__main__":
    # Setup logging
    settings = get_settings()
    setup_logging(settings.log_level)

    # Run application
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)