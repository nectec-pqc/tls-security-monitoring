# NOTE: Can't use distroless to RUN installation
# because it does not have a shell.
FROM ghcr.io/astral-sh/uv:python3.14-alpine AS base
# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1
# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy
# Install libraries
WORKDIR /opt/app
COPY pyproject.toml uv.lock ./
RUN \
  --mount=type=cache,target=/root/.cache/uv \
  uv sync --locked --no-install-project --no-dev
ENV PATH="/opt/app/.venv/bin:$PATH"


FROM base AS dev
RUN \
  --mount=type=cache,target=/root/.cache/uv \
  uv sync --locked --no-install-project
# Install application source code
COPY README.md ./
COPY src src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked
# Switch to non-root executing user, prepare write-able workdir.
USER 1000:1000
WORKDIR /opt/app/workdir
ENTRYPOINT ["app"]
CMD []


FROM base AS base-prod
# Install application source code
COPY README.md ./
COPY --exclude=src/tests src src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev


# Final production image is as small as possible.
# No uv in final image.
FROM python:3.14-alpine AS prod
COPY --from=base-prod /opt/app /opt/app
ENV PATH="/opt/app/.venv/bin:$PATH"
USER 1000:1000
WORKDIR /opt/app/workdir
ENTRYPOINT ["app"]
CMD []
