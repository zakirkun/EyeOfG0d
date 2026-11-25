# syntax=docker/dockerfile:1
#
# Multi-stage build: `docker compose up -d --build` (or `docker build .`) produces
# the complete image from source. No prebuilt binary in the build context is needed,
# so a fresh `git clone` builds — dist/ is git-ignored and is no longer required.
#
#   frontend (web) -> Go binary with embedded UI (build) -> runtime image
#
# The Go binary is produced by build.sh with the same flags the release workflow's
# binaries job uses, so the image binary and the published release binary come from
# one source.

# ---------------------------------------------------------------- frontend ---
# Pinned to the Node 22 line the CI/release workflows use. On the build platform
# only; the frontend static export is architecture-independent.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build:static

# ------------------------------------------------------------- Go binary ---
# Pinned to the Go 1.26 line (matches go.mod and the release binaries job). The
# binary is CGO-free, so this stage runs on the build platform and cross-compiles
# to $TARGETARCH without QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Reuse the frontend built above; build.sh skips its own frontend step.
COPY --from=web /src/web/out ./server/webui/dist
ARG EYEOFG0D_VERSION=dev
ARG TARGETOS
ARG TARGETARCH
# Same flags as the release binaries job (EYEOFG0D_COMPRESS=0, -trimpath,
# -X main.version), driven through build.sh so there is one build path.
RUN EYEOFG0D_SKIP_FRONTEND=1 \
    EYEOFG0D_SKIP_NPM_CI=1 \
    EYEOFG0D_COMPRESS=0 \
    EYEOFG0D_OUTPUT=/out/eyeofg0d \
    EYEOFG0D_BUILD_VERSION="${EYEOFG0D_VERSION}" \
    bash ./build.sh --target "${TARGETOS:-linux}/${TARGETARCH:-amd64}"

# ------------------------------------------------------- third-party tools ---
# Web-recon toolbox (drost-community take 1, #100): pinned release binaries, staged
# on the build platform and copied into /usr/local/bin of the runtime image so hunt
# workers can run them directly through their Bash tool. Versions pinned per tool;
# upgrade deliberately. Each archive is verified against the checksums file of its
# own GitHub release (exact asset name, sha256). That file comes from the same
# release channel as the archive, so it catches corrupted or swapped downloads and
# moved tags, not a compromised publisher. sqlmap has no release binaries: it is a
# shallow clone of a pinned tag, checked against the expected commit.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS tools
ARG TARGETARCH
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.12.0
ARG SUBFINDER_VERSION=v2.17.0
ARG KATANA_VERSION=v1.8.0
ARG FFUF_VERSION=v2.3.0
ARG DALFOX_VERSION=v3.2.4
ARG SQLMAP_VERSION=1.9.9
ARG SQLMAP_COMMIT=cceda39208b5aad478de2c3f731df4239d9881f6
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) PD_ARCH=amd64; FFUF_ARCH=amd64; DALFOX_ARCH=x86_64 ;; \
      arm64) PD_ARCH=arm64; FFUF_ARCH=arm64; DALFOX_ARCH=aarch64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /out; \
    fetch() { base="$1"; asset="$2"; sums="$3"; name="$4"; \
      rm -rf /tmp/t; mkdir -p /tmp/t/x; \
      curl -fsSL "$base/$asset" -o "/tmp/t/$asset"; \
      curl -fsSL "$base/$sums" -o /tmp/t/sums.txt; \
      want="$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1 }' /tmp/t/sums.txt)"; \
      if [ -z "$want" ]; then echo "no checksum entry for $asset" >&2; exit 1; fi; \
      got="$(sha256sum "/tmp/t/$asset" | cut -d' ' -f1)"; \
      if [ "$want" != "$got" ]; then echo "checksum mismatch for $asset: want $want got $got" >&2; exit 1; fi; \
      case "$asset" in *.zip) unzip -q "/tmp/t/$asset" -d /tmp/t/x ;; *) tar -xzf "/tmp/t/$asset" -C /tmp/t/x ;; esac; \
      find /tmp/t/x -type f -name "$name" -exec install -m 0755 {} /out/ \; ; \
      [ -x "/out/$name" ] || { echo "$name not found in $asset" >&2; exit 1; }; \
      rm -rf /tmp/t; }; \
    gh="https://github.com"; \
    fetch "$gh/projectdiscovery/nuclei/releases/download/$NUCLEI_VERSION" \
      "nuclei_${NUCLEI_VERSION#v}_linux_${PD_ARCH}.zip" "nuclei_${NUCLEI_VERSION#v}_checksums.txt" nuclei; \
    fetch "$gh/projectdiscovery/httpx/releases/download/$HTTPX_VERSION" \
      "httpx_${HTTPX_VERSION#v}_linux_${PD_ARCH}.zip" "httpx_${HTTPX_VERSION#v}_checksums.txt" httpx; \
    fetch "$gh/projectdiscovery/subfinder/releases/download/$SUBFINDER_VERSION" \
      "subfinder_${SUBFINDER_VERSION#v}_linux_${PD_ARCH}.zip" "subfinder_${SUBFINDER_VERSION#v}_checksums.txt" subfinder; \
    fetch "$gh/projectdiscovery/katana/releases/download/$KATANA_VERSION" \
      "katana_${KATANA_VERSION#v}_linux_${PD_ARCH}.zip" "katana-${KATANA_VERSION#v}-checksums.txt" katana; \
    fetch "$gh/ffuf/ffuf/releases/download/$FFUF_VERSION" \
      "ffuf_${FFUF_VERSION#v}_linux_${FFUF_ARCH}.tar.gz" "ffuf_${FFUF_VERSION#v}_checksums.txt" ffuf; \
    fetch "$gh/hahwul/dalfox/releases/download/$DALFOX_VERSION" \
      "dalfox-${DALFOX_VERSION}-linux-${DALFOX_ARCH}-musl.tar.gz" "dalfox-${DALFOX_VERSION}-linux-${DALFOX_ARCH}-musl.tar.gz.sha256" dalfox; \
    git clone --quiet --depth 1 --branch "$SQLMAP_VERSION" https://github.com/sqlmapproject/sqlmap /opt/sqlmap; \
    commit="$(git -C /opt/sqlmap rev-parse HEAD)"; \
    if [ "$commit" != "$SQLMAP_COMMIT" ]; then echo "sqlmap commit mismatch: want $SQLMAP_COMMIT got $commit" >&2; exit 1; fi; \
    rm -rf /opt/sqlmap/.git

# ---------------------------------------------------------------- runtime ---
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# Common tools: ripgrep / curl / vim, plus a set of recon staples (add/remove as needed).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip xz-utils \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && rm -rf /var/lib/apt/lists/*
# Node 22 from the official nodejs.org tarball, verified against its SHASUMS256.txt:
# bookworm's apt nodejs is 18, Playwright requires >=20, and 20 is end-of-life.
# 22 matches the CI and release workflows.
ARG NODE_VERSION=22.23.4
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) NODE_ARCH=x64 ;; \
      arm64) NODE_ARCH=arm64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    base="https://nodejs.org/dist/v${NODE_VERSION}"; \
    asset="node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"; \
    curl -fsSL "$base/$asset" -o "/tmp/$asset"; \
    curl -fsSL "$base/SHASUMS256.txt" -o /tmp/SHASUMS256.txt; \
    want="$(awk -v a="$asset" '$2 == a { print $1 }' /tmp/SHASUMS256.txt)"; \
    if [ -z "$want" ]; then echo "no checksum entry for $asset" >&2; exit 1; fi; \
    got="$(sha256sum "/tmp/$asset" | cut -d' ' -f1)"; \
    if [ "$want" != "$got" ]; then echo "checksum mismatch for $asset: want $want got $got" >&2; exit 1; fi; \
    tar -xJf "/tmp/$asset" -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f "/tmp/$asset" /tmp/SHASUMS256.txt; \
    node --version; npm --version
# Pinned, checksum-verified recon binaries and the sqlmap checkout from the tools stage.
COPY --from=tools /out/ /usr/local/bin/
COPY --from=tools /opt/sqlmap /opt/sqlmap
RUN set -eux; \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap; \
    nuclei -version >/dev/null; httpx -version; subfinder -version; katana -version; \
    ffuf -V >/dev/null; dalfox --version >/dev/null; sqlmap --version >/dev/null

# bbot recursive recon orchestrator (#117): blacklanternsecurity/bbot, AGPL-3.0
# (same license as EyeOfG0d; standalone CLI dependency, not linked code). Pinned
# version, own venv to isolate from the image python. Module dependencies are
# preinstalled (--install-all-deps) so scans never need pip at runtime, which
# would fail under a program's egress allowlist.
ARG BBOT_VERSION=3.0.2
# arm64: bbot's Chrome and retirejs's Node are x86-64; use native builds.
RUN set -eux; \
    python -m venv /opt/bbot; \
    /opt/bbot/bin/pip install --no-cache-dir "bbot==${BBOT_VERSION}"; \
    ln -s /opt/bbot/bin/bbot /usr/local/bin/bbot; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends chromium; \
      rm -rf /var/lib/apt/lists/*; \
      bbot_dir="$(/opt/bbot/bin/python -c 'import bbot, os; print(os.path.dirname(bbot.__file__))')"; \
      sed -i 's/linux-x64/linux-arm64/g' "$bbot_dir/modules/retirejs.py"; \
    fi; \
    bbot -y --install-all-deps; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then \
      printf '\nmodules:\n  gowitness:\n    chrome_path: /usr/bin/chromium\n' >> /root/.config/bbot/bbot.yml; \
    fi; \
    bbot --version >/dev/null; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness,retirejs >/dev/null 2>&1 || true; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness,retirejs --no-color >/tmp/bbot-dry.log 2>&1 || true; \
    ! grep -qE "Installing|ERRR|CRITICAL" /tmp/bbot-dry.log || { cat /tmp/bbot-dry.log; exit 1; }


# Preinstall Playwright MCP and CLI (globally) so no network download is needed at runtime.
# @playwright/mcp: the seeded browser MCP runs the playwright-mcp binary directly.
# `npx @playwright/mcp` is not used: it queries the npm registry on every start even
# with the package installed globally.
# @playwright/cli: provides playwright-cli, verified with --help right after install.
# Then install playwright (browser management) and preinstall chromium plus its system
# dependencies via --with-deps. @playwright/mcp and @playwright/cli bundle their own
# playwright-core, which expects a different Chromium build than
# playwright@PLAYWRIGHT_VERSION installs, so that build is installed as well (second
# install line); without it neither can launch a browser. All three packages are
# pinned; upgrade deliberately.
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
ARG PLAYWRIGHT_CLI_VERSION=0.1.22
ARG PLAYWRIGHT_VERSION=1.64.1
# playwright-core's exports map hides cli.js from require.resolve, so run the
# binary npm links for @playwright/mcp instead: it is the copy MCP actually
# loads, and it installs the Chromium revision that copy expects.
RUN npm install -g "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" "@playwright/cli@${PLAYWRIGHT_CLI_VERSION}" "playwright@${PLAYWRIGHT_VERSION}" \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && "$(npm root -g)/@playwright/mcp/node_modules/.bin/playwright-core" install chromium \
    && rm -rf /var/lib/apt/lists/*

# ---- Mobile (Android) toolchain -------------------------------------------
# The static half of the apk flow (docs/mobile-apk-flow.md) is pure Go and needs
# none of this. These are the tools the operator - or an agent through Bash -
# reaches for once the static pass has named a component worth reading:
#
#   jadx      dex -> Java source; the tool used to read an exported component
#   apktool   manifest/resources -> smali, for rebuilds and resource review
#   aapt      manifest dump without a full decode
#   apksigner reports and verifies the signing schemes
#   adb       install, am start, content query: the dynamic entry point
#   frida     CLI, plus frida-server binaries to push to a device
#   ghidra    headless decompiler for the .so files a package ships
#
# Java is the awkward part. apktool/aapt/apksigner are exercised against 17 and
# bookworm ships it, so that stays the shared runtime. Ghidra 12.2 requires a
# full JDK 25, which bookworm does not carry (it is in trixie and later), so
# Temurin 25 is installed alongside and pointed at by Ghidra's own
# JAVA_HOME_OVERRIDE. Two JDKs is deliberate: putting every Android tool on 25
# would move them onto a runtime none of them were tested against.
#
# Every download is checksum-pinned from its publisher's release metadata, the
# same way the recon binaries above are. Nothing is fetched at runtime, so an
# air-gapped deployment keeps the whole toolchain.

ARG JADX_VERSION=1.5.7
ARG JADX_SHA256=1755e4242ade71a077438723689f404079592ec7764a3a0572f98fef94ebcbf3

RUN apt-get update && apt-get install -y --no-install-recommends \
      openjdk-17-jre-headless adb zipalign apktool aapt apksigner \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
      -o /tmp/jadx.zip; \
    got="$(sha256sum /tmp/jadx.zip | cut -d' ' -f1)"; \
    if [ "$got" != "$JADX_SHA256" ]; then echo "jadx checksum mismatch: want $JADX_SHA256 got $got" >&2; exit 1; fi; \
    mkdir -p /opt/jadx; \
    unzip -q /tmp/jadx.zip -d /opt/jadx; \
    chmod +x /opt/jadx/bin/jadx; \
    ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx; \
    rm -f /tmp/jadx.zip; \
    jadx --version; apktool --version; aapt version; apksigner version; adb version

# frida-tools provides the `frida`, `frida-ps` and `frida-trace` CLIs. The
# matching frida-server binaries are unpacked into the image so a device can be
# instrumented without the container reaching the network: arm64 covers real
# handsets, x86_64 covers emulators.
ARG FRIDA_TOOLS_VERSION=14.13.2
ARG FRIDA_SERVER_VERSION=17.27.4
ARG FRIDA_SERVER_ARM64_SHA256=a2007a0f3a8bcbbc3ee165b5d7904970a59b2a769310d751d68cfa405145432f
ARG FRIDA_SERVER_X86_64_SHA256=e30e8d8dcefa6d8b78b5b6a613b42c102d5dfa0e0e47ac7ce27590dc8f05a4db

RUN set -eux; \
    pip install --no-cache-dir --break-system-packages "frida-tools==${FRIDA_TOOLS_VERSION}"; \
    mkdir -p /opt/frida-server; \
    fetch_server() { arch="$1"; want="$2"; \
      url="https://github.com/frida/frida/releases/download/${FRIDA_SERVER_VERSION}/frida-server-${FRIDA_SERVER_VERSION}-android-${arch}.xz"; \
      curl -fsSL "$url" -o "/tmp/fs-${arch}.xz"; \
      got="$(sha256sum "/tmp/fs-${arch}.xz" | cut -d' ' -f1)"; \
      if [ "$got" != "$want" ]; then echo "frida-server ${arch} checksum mismatch: want $want got $got" >&2; exit 1; fi; \
      xz -d -c "/tmp/fs-${arch}.xz" > "/opt/frida-server/frida-server-android-${arch}"; \
      chmod +x "/opt/frida-server/frida-server-android-${arch}"; \
      rm -f "/tmp/fs-${arch}.xz"; \
    }; \
    fetch_server arm64 "$FRIDA_SERVER_ARM64_SHA256"; \
    fetch_server x86_64 "$FRIDA_SERVER_X86_64_SHA256"; \
    frida --version; ls -l /opt/frida-server

# Ghidra, headless only. Two constraints shape this block:
#
#   1. It needs a full JDK 25, not a JRE. Ghidra's launcher runs in "jdk" mode
#      and refuses a bare runtime, which is why Temurin is installed rather than
#      a second apt JRE.
#   2. The official release zip ships native decompiler binaries for
#      linux_x86_64 and win_x86_64 only. On arm64 the Java side imports and
#      disassembles but every decompile fails, because the decompiler is a
#      separate native process. Building it from source on arm64 needs clang and
#      a matching source tag, so arm64 builds skip Ghidra and say so instead of
#      installing something that half-works.
#
# INSTALL_GHIDRA=false skips the roughly 700 MB download and 1.7 GB installed
# footprint; the rest of the mobile toolchain is unaffected.
ARG INSTALL_GHIDRA=true
ARG GHIDRA_VERSION=12.2
ARG GHIDRA_ZIP=ghidra_12.2_PUBLIC_20261016.zip
ARG GHIDRA_SHA256=2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67
ARG JDK25_VERSION=25.0.5.1_2
# The release tag spells the build number with a plus, which must be percent
# encoded in the URL, while the asset filename keeps the underscore.
ARG JDK25_TAG=jdk-25.0.5.1%2B2
ARG JDK25_SHA256=760f91b22c3efc9bd1b64ff950598231be82928cc807e30691a0e7a2995a62c0

RUN set -eux; \
    if [ "${INSTALL_GHIDRA}" != "true" ]; then \
      echo "Ghidra skipped (INSTALL_GHIDRA=${INSTALL_GHIDRA})"; exit 0; \
    fi; \
    if [ "${TARGETARCH:-amd64}" != "amd64" ]; then \
      echo "Ghidra skipped: the release ships no linux_${TARGETARCH} native decompiler"; exit 0; \
    fi; \
    jdk_url="https://github.com/adoptium/temurin25-binaries/releases/download/${JDK25_TAG}/OpenJDK25U-jdk_x64_linux_hotspot_${JDK25_VERSION}.tar.gz"; \
    curl -fsSL "$jdk_url" -o /tmp/jdk25.tar.gz; \
    got="$(sha256sum /tmp/jdk25.tar.gz | cut -d' ' -f1)"; \
    if [ "$got" != "$JDK25_SHA256" ]; then echo "JDK25 checksum mismatch: want $JDK25_SHA256 got $got" >&2; exit 1; fi; \
    mkdir -p /opt/jdk-25; \
    tar -xzf /tmp/jdk25.tar.gz -C /opt/jdk-25 --strip-components=1; \
    rm -f /tmp/jdk25.tar.gz; \
    curl -fsSL "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}" \
      -o /tmp/ghidra.zip; \
    got="$(sha256sum /tmp/ghidra.zip | cut -d' ' -f1)"; \
    if [ "$got" != "$GHIDRA_SHA256" ]; then echo "ghidra checksum mismatch: want $GHIDRA_SHA256 got $got" >&2; exit 1; fi; \
    unzip -q /tmp/ghidra.zip -d /tmp/ghidra-unpack; \
    mv /tmp/ghidra-unpack/ghidra_*_PUBLIC /opt/ghidra; \
    rm -rf /tmp/ghidra.zip /tmp/ghidra-unpack; \
    chmod +x /opt/ghidra/support/analyzeHeadless; \
    ln -sf /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless; \
    printf 'JAVA_HOME_OVERRIDE=/opt/jdk-25\n' >> /opt/ghidra/support/launch.properties; \
    /opt/jdk-25/bin/java -version; \
    test -x /opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile; \
    echo "ghidra ${GHIDRA_VERSION} installed at /opt/ghidra"

WORKDIR /app
# Binary compiled from source in the build stage above.
COPY --from=build /out/eyeofg0d /app/eyeofg0d
# Daemon startup script: relaunches the process after a crash and forwards SIGTERM
# to eyeofg0d — docker stop only signals PID 1; without forwarding, eyeofg0d never receives it,
# cannot shut down gracefully, and is hard-killed by SIGKILL after 10 seconds.
COPY start.sh /app/start.sh
RUN chmod +x /app/eyeofg0d /app/start.sh && mkdir -p /app/keys
COPY skills/ /app/skills/
# persistence points: data/ (traffic index, task files, transcripts) and keys/ (jwt.key, secret.key, via EYEOFG0D_JWT_KEY_DIR)
VOLUME ["/app/data", "/app/keys"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
