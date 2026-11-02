# Demo image for `mcpdoctor scan --sandbox`: contains the example servers and the MCP SDK.
# Build your own the same way: base image + your server's dependencies + your server's code.
FROM python:3.12-slim
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
RUN pip install "mcp>=2.0,<3"
COPY examples /app/examples
WORKDIR /work
