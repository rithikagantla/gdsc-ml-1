"""Shared fixtures. Add sample manifests here so every rule test can reuse them."""

import pytest

from mcpscan.models import ServerManifest, Tool


@pytest.fixture
def hello_manifest() -> ServerManifest:
    return ServerManifest(
        server="00_hello",
        tools=[
            Tool(name="add", description="Add two numbers and return the sum."),
            Tool(name="get_weather", description="Get today's weather for a city."),
        ],
    )
