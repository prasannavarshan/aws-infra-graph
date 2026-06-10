"""Shared test fixtures for infra-agent tests."""

import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"
