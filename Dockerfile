# Image that contains MCPDoctor itself (for CI systems that prefer containers).
FROM python:3.12-slim
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/mcpdoctor
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . && useradd --create-home --uid 10001 doctor
USER doctor
WORKDIR /work
ENTRYPOINT ["mcpdoctor"]
CMD ["--help"]
