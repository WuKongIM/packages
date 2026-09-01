FROM ubuntu:24.04@sha256:1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        apt-utils \
        ca-certificates \
        createrepo-c \
        dpkg-dev \
        findutils \
        gnupg \
        gzip \
        jq \
        python3 \
        rpm \
        zstd \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 signer \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent signer

LABEL org.opencontainers.image.source="https://github.com/WuKongIM/packages" \
      org.opencontainers.image.title="WuKongIM native-package signing toolchain" \
      org.opencontainers.image.description="Network-isolated APT/RPM repository signing and verification tools"

USER 65532:65532
WORKDIR /work

ENTRYPOINT []
CMD ["bash", "--version"]
