# Caddy with a DNS provider's module, for wildcard certificates, which take
# ACME's DNS challenge (see compose.wildcard.yaml). Cloudflare's by default;
# for another provider, set DNS_MODULE to its module
# (https://github.com/caddy-dns), and change the `dns` line of
# Caddyfile.wildcard to match.
ARG CADDY_VERSION=2.10

FROM docker.io/library/caddy:${CADDY_VERSION}-builder AS builder
ARG DNS_MODULE=github.com/caddy-dns/cloudflare
RUN xcaddy build --with ${DNS_MODULE}

FROM docker.io/library/caddy:${CADDY_VERSION}
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
