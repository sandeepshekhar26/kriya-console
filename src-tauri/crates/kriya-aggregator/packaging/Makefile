# packaging/Makefile — one entry point for every kriyaD shipping skin (SHIP-REL).
#
#   make -C packaging static            # static musl kriyad + kriya-audit (both arches, Docker)
#   make -C packaging box               # BOX tarballs (x86_64 + aarch64)
#   make -C packaging image             # distroless OCI image (linux/amd64) + saved tar
#   make -C packaging airgap            # cosign key-signed air-gap bundle (needs COSIGN_KEY)
#   make -C packaging release           # static → box → image → airgap → RELEASE-SHA256SUMS
#
# The air-gap bundle needs the user-held release key:
#   COSIGN_KEY=/path/kriya-release.key COSIGN_PASSWORD=… make -C packaging airgap
# Everything lands in ../build/dist/ (gitignored — rebuilt from these targets).

AGG     := $(abspath $(CURDIR)/..)
DIST    := $(AGG)/build/dist
VERSION := $(shell grep -m1 '^version' $(AGG)/Cargo.toml | cut -d'"' -f2)
ARCHES  ?= x86_64 aarch64
IMG_ARCH ?= x86_64

.PHONY: static box image airgap sums release clean

static:
	bash $(AGG)/build/build-static.sh

box:
	@for a in $(ARCHES); do ARCH=$$a bash $(CURDIR)/box/make-box.sh; done

image:
	ARCH=$(IMG_ARCH) bash $(CURDIR)/build-image.sh
	docker save kriyad:$(VERSION) -o $(DIST)/kriyad-$(VERSION)-image-$(IMG_ARCH).tar
	( cd $(DIST) && shasum -a 256 kriyad-$(VERSION)-image-$(IMG_ARCH).tar > kriyad-$(VERSION)-image-$(IMG_ARCH).tar.sha256 )

airgap:
	ARCH=$(IMG_ARCH) bash $(CURDIR)/airgap/make-bundle.sh

# One top-level manifest over every release artifact (per-skin .sha256 files stay too).
sums:
	( cd $(DIST) && shasum -a 256 kriyad-$(VERSION)-* kriya-release.pub 2>/dev/null > RELEASE-SHA256SUMS ) || \
	( cd $(DIST) && shasum -a 256 kriyad-$(VERSION)-* > RELEASE-SHA256SUMS )
	@echo "==> $(DIST)/RELEASE-SHA256SUMS"; cat $(DIST)/RELEASE-SHA256SUMS

release: static box image airgap sums

clean:
	rm -rf $(DIST)
