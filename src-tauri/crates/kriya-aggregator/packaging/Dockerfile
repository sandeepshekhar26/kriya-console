# kriyad — minimal distroless OCI image (SHIP-IMG).
#
# Expects the STATIC musl binary from build/build-static.sh (COPY-in, no in-image compile) so the image
# is tiny (<15MB), reproducible, and has zero shell / package manager / libc surface. distroless-static +
# nonroot = the smallest defensible base for a single static binary. Runtime state (the SQLite file), the
# offline `control-plane` license, and the mTLS CA are mounted (volume / read-only) — nothing baked in,
# no egress. The build context is a dir containing just this Dockerfile + the `kriyad` binary (see
# packaging/build-image.sh).
FROM gcr.io/distroless/static-debian12:nonroot
COPY kriyad /kriyad
USER nonroot
EXPOSE 8443
ENTRYPOINT ["/kriyad"]
