# Real Android Emulator sidecar for ARTEX.
#
# This image runs a genuine QEMU-backed Android Emulator with a pinned AVD. It
# is linux/amd64 only: the pinned system image is x86_64 and the runtime needs
# host /dev/kvm. KVM itself is supplied by the host at run time, not here.
#
# Pinning strategy: the command-line tools archive is pinned by URL + SHA-256
# and unpacked directly. The remaining SDK packages are installed through
# sdkmanager from the stable channel, which is what registers the package
# metadata that avdmanager and the emulator require; every installed package's
# revision is then asserted against this file, so a drift or a different
# resolution fails the build instead of silently shipping another runtime.
#
# Licensing: these are Google Android SDK components under the Android SDK
# License Agreement. Licenses are accepted non-interactively during the build
# and the license text is retained in the image. Do not redistribute this image
# or the underlying SDK archives without reviewing those terms.

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY main.go android_linux.go android_other.go ops.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/emulator-sidecar .

FROM debian:bookworm-slim

ARG ANDROID_SDK_ROOT=/opt/android-sdk

# Command-line tools build 15859902. SHA-256 is published on the Android
# command-line tools download page.
ARG CMDLINE_TOOLS_URL=https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip
ARG CMDLINE_TOOLS_SHA256=4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583

# Pinned package revisions, asserted after installation.
#   emulator       37.3.10  emulator-linux_x64-16970787.zip
#                          sha1 5f7314368fc6c05c937f6991bb4106214dc389e7
#   platform-tools 37.0.3   platform-tools_r37.0.3-linux.zip
#                          sha1 e1579b288a7ae4e9bc28dedec6a154d78b3c04ed
#   system image   9        x86_64-35_r09.zip
#                          sha1 0103e6dab21290c4b9d16550a3ce99476f884eef
ARG EMULATOR_REVISION=37.3.10
ARG PLATFORM_TOOLS_REVISION=37.0.3
ARG SYSTEM_IMAGE_REVISION=9

ARG SDK_LICENSE_URL=https://dl.google.com/android/repository/repository2-1.xml

ENV ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT} \
    ANDROID_HOME=${ANDROID_SDK_ROOT} \
    ANDROID_USER_HOME=/var/lib/artex-emulator/android-home \
    ANDROID_AVD_HOME=/var/lib/artex-emulator/avd \
    EMULATOR_STATE_DIR=/var/lib/artex-emulator \
    PATH=${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/emulator:/usr/local/bin:/usr/bin:/bin \
    DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

# sdkmanager/avdmanager are Java programs, so a headless JRE is required. The
# rest are the shared libraries the emulator and its Qt runtime link against
# when running headless. The build itself is the test: the assertion steps below
# execute `emulator -version` and create a real AVD, so any missing library
# fails the build instead of shipping a broken image.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        unzip \
        procps \
        openjdk-17-jre-headless \
        libpulse0 \
        libasound2 \
        libx11-6 \
        libxcb1 \
        libxext6 \
        libxrender1 \
        libxtst6 \
        libxi6 \
        libxcursor1 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libxss1 \
        libxt6 \
        libxkbfile1 \
        libxkbcommon0 \
        libxkbcommon-x11-0 \
        libglib2.0-0 \
        libdbus-1-3 \
        libfontconfig1 \
        libfreetype6 \
        libnss3 \
        libgl1 \
        libglu1-mesa \
        zlib1g \
        libtinfo6; \
    rm -rf /var/lib/apt/lists/*

# Install the pinned command-line tools, verifying the published SHA-256. These
# are unpacked directly because they are the toolchain used for everything else
# and do not need SDK package registration.
RUN set -eux; \
    mkdir -p "${ANDROID_SDK_ROOT}/cmdline-tools"; \
    tmp="$(mktemp -d)"; \
    curl -fsSL "$CMDLINE_TOOLS_URL" -o "$tmp/cmdline-tools.zip"; \
    want="$(printf '%s' "$CMDLINE_TOOLS_SHA256" | tr 'A-F' 'a-f')"; \
    got="$(sha256sum "$tmp/cmdline-tools.zip" | cut -d' ' -f1)"; \
    if [ "$got" != "$want" ]; then \
        echo "command-line tools digest mismatch: want $want got $got" >&2; \
        exit 1; \
    fi; \
    unzip -q "$tmp/cmdline-tools.zip" -d "$tmp/unpack"; \
    mv "$tmp/unpack/cmdline-tools" "${ANDROID_SDK_ROOT}/cmdline-tools/latest"; \
    rm -rf "$tmp"; \
    sdkmanager --sdk_root="${ANDROID_SDK_ROOT}" --version

# Accept the Android SDK licenses non-interactively and keep the license text.
# This must run before package installation.
RUN set -eux; \
    mkdir -p "${ANDROID_SDK_ROOT}/licenses"; \
    curl -fsSL "$SDK_LICENSE_URL" -o "${ANDROID_SDK_ROOT}/licenses/android-sdk-repository.xml"; \
    yes | sdkmanager --sdk_root="${ANDROID_SDK_ROOT}" --licenses >/dev/null; \
    test -s "${ANDROID_SDK_ROOT}/licenses/android-sdk-license"; \
    grep -Eq '[0-9a-f]{40}' "${ANDROID_SDK_ROOT}/licenses/android-sdk-license"

# Install the emulator, platform-tools and the x86_64 Google APIs system image
# from the stable channel. sdkmanager validates the archives against the
# checksums in Google's repository metadata while downloading.
RUN set -eux; \
    sdkmanager --sdk_root="${ANDROID_SDK_ROOT}" --channel=0 --verbose \
        "platform-tools" \
        "emulator" \
        "system-images;android-35;google_apis;x86_64"; \
    rm -rf "${ANDROID_SDK_ROOT}/.temp" "${ANDROID_SDK_ROOT}/.downloadIntermediates"

# Fail the build unless the installed revisions are exactly the pinned ones.
# This is what prevents a silently different runtime from being shipped when
# Google advances a channel or a download changes.
RUN set -eux; \
    test -x "${ANDROID_SDK_ROOT}/emulator/emulator"; \
    test -x "${ANDROID_SDK_ROOT}/platform-tools/adb"; \
    test -x "${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/avdmanager"; \
    emu_rev="$(sed -n 's/^Pkg\.Revision=//p' "${ANDROID_SDK_ROOT}/emulator/source.properties")"; \
    pt_rev="$(sed -n 's/^Pkg\.Revision=//p' "${ANDROID_SDK_ROOT}/platform-tools/source.properties")"; \
    img="${ANDROID_SDK_ROOT}/system-images/android-35/google_apis/x86_64"; \
    img_rev="$(sed -n 's/^Pkg\.Revision=//p' "$img/source.properties")"; \
    echo "installed emulator=$emu_rev platform-tools=$pt_rev system-image=$img_rev"; \
    test "$emu_rev" = "$EMULATOR_REVISION"; \
    test "$pt_rev" = "$PLATFORM_TOOLS_REVISION"; \
    test "$img_rev" = "$SYSTEM_IMAGE_REVISION"; \
    grep -qx 'AndroidVersion.ApiLevel=35' "$img/source.properties"; \
    grep -qx 'SystemImage.Abi=x86_64' "$img/source.properties"; \
    grep -qx 'SystemImage.TagId=google_apis' "$img/source.properties"; \
    "${ANDROID_SDK_ROOT}/emulator/emulator" -version | grep -Fq "version $EMULATOR_REVISION"

# Prove the SDK layout is usable end to end: avdmanager must resolve the pinned
# system image and write a real AVD definition bound to it. AVD creation needs
# no KVM, so this is a genuine build-time check rather than an assumption.
#
# Note on --device: cmdline-tools alone does not ship the device-definition
# catalogue, so avdmanager may print "Could not load devices" and fall back to
# its default hardware profile while still exiting 0. That is acceptable here
# (screen geometry does not affect install/am/logcat), but it means the created
# config must be asserted instead of assuming --device took effect. The binding
# that actually matters is image.sysdir.1, which is checked below; the image's
# own identity (API level, ABI, tag) is already asserted in the step above.
RUN set -eux; \
    smoke=/tmp/avd-smoke; \
    mkdir -p "$smoke"; \
    ANDROID_AVD_HOME="$smoke" avdmanager create avd \
        --force \
        --name artex-smoke \
        --package 'system-images;android-35;google_apis;x86_64' \
        --device pixel_2 < /dev/null > "$smoke/create.log" 2>&1; \
    cat "$smoke/create.log"; \
    test -f "$smoke/artex-smoke.ini"; \
    cfg="$smoke/artex-smoke.avd/config.ini"; \
    test -f "$cfg"; \
    echo "--- created AVD config ---"; \
    cat "$cfg"; \
    echo "--------------------------"; \
    grep -Eq '^image\.sysdir\.1=.*system-images/android-35/google_apis/x86_64/?$' "$cfg"; \
    rm -rf "$smoke"

# The emulator runs unprivileged. /dev/kvm is mapped in by the host; if its
# group does not match this user, Compose must grant access explicitly.
#
# bookworm-slim ships no user database tools, so `passwd` (which provides
# groupadd/useradd) is installed here rather than in the library layer above:
# that keeps the expensive, pinned SDK layers valid.
#
# Those binaries live in /usr/sbin, which is deliberately not on this image's
# pinned PATH (see ENV above), so they are invoked by absolute path. Calling
# them by bare name fails with "not found" even after the package is installed.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends passwd; \
    rm -rf /var/lib/apt/lists/*; \
    /usr/sbin/groupadd -g 61050 artex; \
    /usr/sbin/useradd -u 61050 -g 61050 -m -d /var/lib/artex-emulator -s /usr/sbin/nologin artex; \
    mkdir -p "${ANDROID_USER_HOME}" "${ANDROID_SDK_ROOT}/.android" /var/lib/artex-emulator/tasks; \
    chown -R artex:artex "${ANDROID_USER_HOME}" /var/lib/artex-emulator "${ANDROID_SDK_ROOT}/.android"

COPY --from=build /out/emulator-sidecar /app/emulator-sidecar

USER artex
EXPOSE 8090

# This health check may only claim the supervisor is alive. It is explicitly
# not evidence that an emulator booted; the backend requires ADB proof before
# it will report `ready`.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-fsS", "-o", "/dev/null", "http://127.0.0.1:8090/healthz"]

ENTRYPOINT ["/app/emulator-sidecar"]
