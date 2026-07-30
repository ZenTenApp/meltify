# Multi-platform Dockerfile for dockers_v2
# GoReleaser places binaries in platform-specific directories (e.g., linux/amd64/meltify)
FROM gcr.io/distroless/static

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# For ARM variants (e.g., arm/v7), TARGETVARIANT contains the variant (v7).
# The expansion ${TARGETVARIANT:+/${TARGETVARIANT}} adds /v7 only when set.
COPY ${TARGETOS}/${TARGETARCH}${TARGETVARIANT:+/${TARGETVARIANT}}/meltify /usr/local/bin/meltify

ENTRYPOINT [ "/usr/local/bin/meltify" ]
