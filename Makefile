build:
	mkdir -p ${BFAOS}/../build_milestone_1/
	./bfdocker.sh /source/hake/hake.sh -s /source/ -a armv8
	# ./bfdocker.sh make armv8_aos_m0_image.efi
	./bfdocker.sh make -j7 imx8x
	./bfdocker.sh usbboot_imx8x
install:
	./tools/imx8x/bf-boot.sh --bf ${BFAOS}/../build_milestone_1/armv8_aos_m0_image.efi
monitor:
	picocom -b 115200 -f n /dev/ttyUSB0
klog:
	sudo dmesg -wH

clean:
	rm -rf ${BFAOS}/../build_milestone_1/*
