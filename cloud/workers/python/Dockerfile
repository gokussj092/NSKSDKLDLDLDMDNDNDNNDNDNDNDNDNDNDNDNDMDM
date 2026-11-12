# Worker sandbox image. Build context MUST be the repository root (see compose.yaml).
FROM node:22-bookworm-slim AS js-deps
WORKDIR /opt/spdecode
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends php-cli libstdc++6 libatomic1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=js-deps /usr/local/bin/node /usr/local/bin/node
# The worker uses the Node binary for .hat and other legacy formats.
# Fail image builds if a runtime loader dependency is missing.
RUN node --version >/dev/null
WORKDIR /opt/spdecode
COPY requirements.txt package.json package-lock.json ./
RUN pip install --no-cache-dir -r requirements.txt
# The root npm dependencies are used by a small number of legacy JS engines.
COPY --from=js-deps /opt/spdecode/node_modules ./node_modules
COPY decoders/ ./decoders/
COPY spdecode/ ./spdecode/
COPY decoders.json ./decoders.json
COPY docs/cloud/C0_FORMAT_MATRIX.csv ./docs/cloud/C0_FORMAT_MATRIX.csv
COPY cloud/workers/python/engine.py cloud/workers/python/server.py cloud/workers/python/text_bridge.py cloud/workers/python/hc_bridge.py cloud/workers/python/catalog_bridge.py cloud/workers/python/catalog_vpn_bridge.py cloud/workers/python/hat_complete.js ./cloud/workers/python/
COPY cloud/workers/python/mkk_bundle.py cloud/workers/python/ultra_custom_bridge.py cloud/workers/python/npvs_bridge.py ./cloud/workers/python/
COPY cloud/workers/python/dark_bridge.py cloud/workers/python/v2box_bridge.py ./cloud/workers/python/
COPY cloud/workers/python/exports/ ./cloud/workers/python/exports/
# Same verified file-format catalog shared by web and worker (no private keys).
COPY cloud/web/content/file-formats.json ./cloud/web/content/file-formats.json
# VPS installer clones the source as root with umask 077: files can be 0600
# and directories 0700. Docker COPY preserves modes. The restricted runtime
# UID 65532 cannot read server.py or traverse decoders/ unless we normalize
# SOURCE permissions in this container image. No private credentials are copied.
RUN chmod -R a+rX /opt/spdecode
# Fail the image build immediately if the actual nonroot account cannot import
# the server entry point and inspect the canonical engine inventory.
USER 65532:65532
RUN python -B -c "import sys; from pathlib import Path; sys.path.insert(0,'cloud/workers/python'); from engine import load_file_engines; assert len(load_file_engines()) == 240; from server import WorkerHandler; from decoders.Python import npvs; from npvs_bridge import main as npvs_main; assert Path('cloud/workers/python/npvs_bridge.py').is_file(); assert Path('cloud/workers/python/v2box_bridge.py').is_file(); assert callable(npvs_main); print('SP-DECODE worker: nonroot imports and NPVS credential bridge OK')"
# Exercise the genuine isolated Hat worker subprocess as uid 65532, not only
# Node startup. A synthetic encrypted document keeps user profiles out of images.
RUN python -B -c 'import base64,json,sys;from Crypto.Cipher import AES;from Crypto.Util.Padding import pad;sys.path.insert(0,"cloud/workers/python");from engine import decode_file;key=base64.b64decode("zbNkuNCGSLivpEuep3BcNA==");document={"profilev5":{"custom_host":None},"metadata":{"synthetic":True}};raw=json.dumps(document).encode();encrypted=base64.b64encode(AES.new(key,AES.MODE_ECB).encrypt(pad(raw,16)));result=decode_file("hat",encrypted,full_hat=True);assert result["structuredJson"]==document;print("SP-DECODE Hat Cloud synthetic smoke OK")'
# Package and local import work from the original repository tree.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 WORKER_BIND_HOST=0.0.0.0 WORKER_PORT=8787
EXPOSE 8787
CMD ["python", "-B", "cloud/workers/python/server.py"]
