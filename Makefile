.PHONY: all
all: hake build

.PHONY: hake
hake:
	./tools/bfpodman.sh /source/hake/hake.sh -s /source/ -a armv8

.PHONY: build
build:
	./tools/bfpodman.sh make -j7 imx8x

.PHONY: _install
_install:
	./tools/imx8x/bf-boot.sh --bf build/armv8_imx8x_image.efi

.PHONY: install
install: build _install

.PHONY: monitor
monitor:
	minicom -b 115200 -D /dev/ttyUSB0

.PHONY: tags
tags:
	@ctags -R \
	    --sort=yes \
	    --totals=yes \
	    --languages=C \
	    --langmap=c:+.h \
	    --exclude=.git \
	    --exclude=build \
	    --extra=+f \
	    .
