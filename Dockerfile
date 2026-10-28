# The Cairn image: the static binary from build-release.sh, which builds it for
# the machine it runs on, into dist/<amd64|arm64>/cairn. The release workflow
# (.github/workflows/release.yml) builds both and pushes the image for both, so
# it holds the exact binaries attached to the release. By hand:
#
#   ./build-release.sh && docker build -t cairn .
#
# Configure it through the environment: every flag of `cairn serve` has a
# CAIRN_* variable (see README.md). Set at least CAIRN_DATABASE; for more than
# one node, also CAIRN_PEER_URL, since peers can't reach this node at 0.0.0.0.
# `cairn role …` reads CAIRN_DATABASE too, so it works as is in the container.

FROM gcr.io/distroless/static-debian13

ARG TARGETARCH
COPY --chmod=755 dist/${TARGETARCH}/cairn /usr/local/bin/cairn
COPY LICENSE NOTICE README.md /usr/share/doc/cairn/

ENV CAIRN_DATA_DIR=/var/lib/cairn \
    CAIRN_LISTEN_CLIENT=0.0.0.0:9000 \
    CAIRN_LISTEN_PEER=0.0.0.0:9431
VOLUME /var/lib/cairn
# The S3 API, and the peer endpoint with the dashboard. The latter is
# unauthenticated, so don't publish it beyond a trusted network.
EXPOSE 9000 9431

ENTRYPOINT ["/usr/local/bin/cairn"]
CMD ["serve"]
