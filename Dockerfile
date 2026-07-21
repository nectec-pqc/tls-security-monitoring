FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim AS base
RUN \
  groupadd --gid 1000 tlssec && \
  useradd \
    --no-log-init \
    --create-home \
    --shell /bin/bash \
    --uid 1000 \
    --gid 1000 \
    tlssec
RUN apt-get update && apt-get install -y --no-install-recommends \
  testssl.sh \
  nmap \
  && rm -rf /var/lib/apt/lists/*
# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1
# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy
# Install libraries
WORKDIR /opt/app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
  uv sync --locked --no-install-project --no-dev
ENV PATH="/opt/app/.venv/bin:$PATH"


FROM base AS dev
RUN apt-get update && apt-get install -y --no-install-recommends \
  openssh-server \
  && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/root/.cache/uv \
  uv sync --locked --no-install-project
# Install application source code
COPY README.md ./
COPY src src/
RUN --mount=type=cache,target=/root/.cache/uv \
  uv sync --locked
USER 1000:1000
WORKDIR /opt/app/.pytest_cache
WORKDIR /home/tlssec
ENTRYPOINT ["tlssec"]
CMD []


FROM base AS analysis
# TODO: make non-app installation work as separate layer
#RUN --mount=type=cache,target=/root/.cache/uv \
#  uv sync --locked --no-install-project --extra analysis
# Install application source code
COPY README.md ./
COPY src src/
RUN --mount=type=cache,target=/root/.cache/uv \
  uv sync --locked --extra analysis
USER 1000:1000
WORKDIR /opt/app/.pytest_cache
WORKDIR /home/tlssec
ENTRYPOINT ["jupyter", "lab", "--ip=0.0.0.0"]
CMD []


FROM base AS base-prod
# Install application source code
COPY README.md ./
COPY --exclude=src/tests src src/
RUN --mount=type=cache,target=/root/.cache/uv \
  uv sync --locked --no-dev


# Final production image is as small as possible.
# No uv in final image.
FROM python:3.14-slim-trixie AS prod
COPY --from=base-prod /opt/app /opt/app
ENV PATH="/opt/app/.venv/bin:$PATH"
USER 1000:1000
WORKDIR /home/tlssec
ENTRYPOINT ["tlssec"]
CMD []
