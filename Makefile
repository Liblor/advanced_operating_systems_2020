build:
	./bfdocker.sh /source/hake/hake.sh -s /source/ -a armv8
	./bfdocker.sh make -j7 imx8x
install:
	./tools/imx8x/bf-boot.sh --bf ${BFAOS}/../build_milestone_1/armv8_imx8x_image.efi
monitor:
	picocom -b 115200 -f n /dev/ttyUSB0
klog:
	sudo dmesg -wH

clean:
	rm -rf ${BFAOS}/../build_milestone_1/*
