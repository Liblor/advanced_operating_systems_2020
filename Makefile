BUILD_DIR=$(HOME)/aos-m1-build

.PHONY: all
all: build install

.PHONY: build
build:

	./tools/bfdocker.sh make -j7 imx8x

.PHONY: install
install:
	tools/imx8x/bf-boot.sh --bf $(BUILD_DIR)/armv8_imx8x_image.efi

.PHONY: hake
hake:
	./tools/bfdocker.sh /source/hake/hake.sh -s /source

.PHONY: monitor
monitor:
	minicom -b 115200 -D /dev/ttyUSB0 minirc.dfl

.PHONY: tags
tags:
	ctags \
		--recurse=yes \
		--sort=foldcase \
		--totals=yes \
		--extra=+f \
		-h .c.h \
		--exclude=.git\
		.

.PHONY: clean
clean:
	rm -rf tags
	rm -r $(BUILD_DIR)/*
