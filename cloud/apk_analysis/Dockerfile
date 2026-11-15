# F7-A0-P03: separate OFFLINE analysis candidate, NOT the production decoder-worker.
# Build this image once per tool/dependency update; NEVER pip install per APK.
# Current direct pins are retained unchanged; transitive hash locking is P01 pending.
FROM python:3.12-slim-bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_DATA_HOME=/tmp/.local/share \
    JAVA_TOOL_OPTIONS="-Duser.home=/tmp"
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless libstdc++6 libcairo2 libpango-1.0-0 libffi8 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/spdecode
COPY scripts/apk_analysis/requirements.txt /tmp/apk-analysis-requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/apk-analysis-requirements.txt
# Only reviewed candidate files enter the image; other functional research
# scripts remain in Git until individually approved for this runtime.
COPY scripts/apk_analysis/inspect_apk.py scripts/apk_analysis/decompile.py \
     scripts/apk_analysis/requirements.txt ./scripts/apk_analysis/
COPY cloud/apk_analysis/__init__.py cloud/apk_analysis/runtime_preflight.py \
     cloud/apk_analysis/workspace.py ./cloud/apk_analysis/
RUN mkdir -p /opt/spdecode/scripts/apk_analysis/cache && \
    chown -R 65532:65532 /opt/spdecode && chmod -R a+rX /opt/spdecode
USER 65532:65532
# Sources/dependencies are installed in image layers. The verified JADX jar is
# cached in a separate named volume by the maintenance service, never by a job.
CMD ["python", "-B", "cloud/apk_analysis/runtime_preflight.py", "--check"]
