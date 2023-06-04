import pytest
import docker
import subprocess
import os
import psycopg
import time

@pytest.fixture(scope="session")
def docker_client():
    return docker.from_env()

@pytest.fixture(scope="session")
def docker_compose_file(pytestconfig):
    return str(pytestconfig.rootdir.join("docker-compose.yml"))

@pytest.fixture(scope="session")
def docker_compose(docker_client, docker_compose_file):
    # Make sure the Docker containers are stopped and removed before starting
    subprocess.run(["docker-compose", "down"], cwd=os.path.dirname(os.path.abspath(__file__)))
    # Start the Docker containers
    subprocess.run(["docker-compose", "up", "-d"], cwd=os.path.dirname(os.path.abspath(__file__)))

    # Wait for the containers to start up
    max_retries = 10
    retry_count = 0
    while retry_count < max_retries:
        try:
            postgres_container = docker_client.containers.get("pg-mgt-utils_postgres_1")
            if postgres_container.status == "running":
                break
        except:
            pass
        retry_count += 1
        time.sleep(1)
    else:
        raise Exception("Docker containers did not start up")

    while retry_count < max_retries:
        try:
            conn = psycopg.connect(
                host="0.0.0.0",
                port=5432,
                user="postgres",
                password="Password123",
                dbname="postgres"
            )
            conn.close()
            break
        except:
            pass
        time.sleep(1)
        retry_count += 1
    else:
        raise Exception("PostgreSQL did not start up correctly")


    yield docker_compose_file

    # Stop and remove the Docker containers
    subprocess.run(["docker-compose", "down"], cwd=os.path.dirname(os.path.abspath(__file__)))