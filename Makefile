BUILD_DIR?="../build"

.PHONY: build
build:
	./bfdocker.sh ${BUILD_DIR} /source/hake/hake.sh -s /source/ -a armv8
	./bfdocker.sh ${BUILD_DIR} make -j7 imx8x

.PHONY: install
install:
	./tools/imx8x/bf-boot.sh --bf ${BUILD_DIR}/armv8_imx8x_image.efi

.PHONY: monitor
monitor:
	picocom -b 115200 -f n /dev/ttyUSB0
