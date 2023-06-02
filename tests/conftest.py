import pytest
import docker
from pathlib import Path
import os



COMPOSE_FILE = "docker-compose.yml"


@pytest.fixture(scope="session")
def docker_compose_file(pytestconfig):
    return os.path.join(str(pytestconfig.rootdir), COMPOSE_FILE)

@pytest.fixture(scope="session", autouse=True)
def cleanup_previous_containers():
    client = docker.from_env()
    container_name_pattern = "pytest"
    network_name_pattern = "pytest_docker_compose"

    for container in client.containers.list(all=True):
        if container_name_pattern in container.name:
            container.stop()
            container.remove()

    # Remove the network
    for network in client.networks.list():
        if network_name_pattern in network.name:
            network.remove()

    yield


@pytest.fixture(scope="session")
def docker_containers(cleanup_previous_containers, docker_compose_file):
    containers = {}

    containers['postgres'] = {"host": "localhost", "port": 5432}

    yield containers

    client = docker.from_env()
    for container in client.containers.list(filters={"label": "pytest_docker_compose"}):
        container.stop()
        container.remove()


