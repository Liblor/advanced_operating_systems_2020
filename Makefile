build:
	./bfdocker.sh /source/hake/hake.sh -s /source/
	./bfdocker.sh make armv8_aos_m0_image.efi
install:
	./tools/imx8x/bf-boot.sh --bf ${BFAOS}/../build_milestone_1/armv8_aos_m0_image.efi
monitor:
	picocom -b 115200 -f n /dev/ttyUSB0
klog:
	sudo dmesg -wH

clean:
	rm -rf ${BFAOS}/../build_milestone_1/*
