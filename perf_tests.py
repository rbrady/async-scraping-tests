import asyncio
import time

import amazon as async_amazon

from anchore_enterprise.services.feeds.drivers.amazon import data as legacy
from anchore_engine.decorators import profile


@profile
def legacy_feed_load():
    """Load the Amazon ALAS vulnerability data using the legacy driver from Enterprise."""
    summary_count = 0

    generator, state = legacy.fetch(task_id=42, skip_if_exists=False, previous_state=None, config=None)

    for item in generator:
        summary_count += 1
        print(f"{summary_count:03} {item}")
    return summary_count


@profile
async def async_feed_load():
    """Load the Amazon ALAS vulnerability data with the asyncio driver."""
    summary_count = 0

    async for item in async_amazon.items():
        summary_count += 1
        print(f"{summary_count:03} {item}")
    return summary_count


if __name__ == "__main__":
    legacy_start_time = time.time()
    legacy_count = legacy_feed_load()
    legacy_total_time = time.time() - legacy_start_time

    async_start_time = time.time()
    async_count = asyncio.run(async_feed_load())
    async_total_time = time.time() - async_start_time

    print(f"Processed {legacy_count} in {legacy_total_time:.2f} seconds.")
    print(f"Processed {async_count} in {async_total_time:.2f} seconds.")
