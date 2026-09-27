import asyncio
import logging

from app.proxy import serve

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

if __name__ == "__main__":
    asyncio.run(serve())
