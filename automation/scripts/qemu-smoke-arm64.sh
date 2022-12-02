#!/bin/bash

set -ex

test_variant=$1

if [ -z "${test_variant}" ]; then
    passed="ping test passed"
    domU_check="
until ifconfig eth0 192.168.0.2 &> /dev/null && ping -c 10 192.168.0.1; do
    sleep 30
done
echo \"${passed}\"
"
fi

if [[ "${test_variant}" == "static-mem" ]]; then
    # Memory range that is statically allocated to DOM1
    domu_base="50000000"
    domu_size="10000000"
    passed="${test_variant} test passed"
    domU_check="
current=\$(hexdump -e '16/1 \"%02x\"' /proc/device-tree/memory@${domu_base}/reg 2>/dev/null)
expected=$(printf \"%016x%016x\" 0x${domu_base} 0x${domu_size})
if [[ \"\${expected}\" == \"\${current}\" ]]; then
	echo \"${passed}\"
fi
"
fi

if [[ "${test_variant}" == "boot-cpupools" ]]; then
    # Check if domU0 (id=1) is assigned to Pool-1 with null scheduler
    passed="${test_variant} test passed"
    dom0_check="
if xl list -c 1 | grep -q Pool-1 && xl cpupool-list Pool-1 | grep -q Pool-1; then
    echo ${passed}
fi
"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get -qy update
apt-get -qy install --no-install-recommends u-boot-qemu \
                                            u-boot-tools \
                                            device-tree-compiler \
                                            busybox-static \
                                            cpio \
                                            curl

# XXX QEMU looks for "efi-virtio.rom" even if it is unneeded
curl -fsSLO https://github.com/qemu/qemu/raw/v5.2.0/pc-bios/efi-virtio.rom
./binaries/qemu-system-aarch64 \
   -machine virtualization=true \
   -cpu cortex-a57 -machine type=virt \
   -m 1024 -smp 2 -display none \
   -machine dumpdtb=binaries/virt-gicv2.dtb

# XXX disable pl061 to avoid Linux crash
fdtput binaries/virt-gicv2.dtb -p -t s /pl061@9030000 status disabled

# Busybox
mkdir -p initrd
mkdir -p initrd/bin
mkdir -p initrd/sbin
mkdir -p initrd/etc
mkdir -p initrd/dev
mkdir -p initrd/proc
mkdir -p initrd/sys
mkdir -p initrd/lib
mkdir -p initrd/var
mkdir -p initrd/mnt
cp /bin/busybox initrd/bin/busybox
initrd/bin/busybox --install initrd/bin
echo "#!/bin/sh

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
${domU_check}
/bin/sh" > initrd/init
chmod +x initrd/init
cd initrd
find . | cpio --create --format='newc' | gzip > ../binaries/initrd
cd ..

# DOM0 rootfs
mkdir -p rootfs
cd rootfs
tar xzf ../binaries/initrd.tar.gz
mkdir proc
mkdir run
mkdir srv
mkdir sys
rm var/run
cp -ar ../binaries/dist/install/* .

echo "#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/lib
bash /etc/init.d/xencommons start

/usr/local/lib/xen/bin/init-dom0less

brctl addbr xenbr0
brctl addif xenbr0 eth0
ifconfig eth0 up
ifconfig xenbr0 up
ifconfig xenbr0 192.168.0.1

xl network-attach 1 type=vif
${dom0_check}
" > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
echo "rc_verbose=yes" >> etc/rc.conf
find . | cpio -H newc -o | gzip > ../binaries/dom0-rootfs.cpio.gz
cd ..

# ImageBuilder
echo 'MEMORY_START="0x40000000"
MEMORY_END="0x80000000"

DEVICE_TREE="virt-gicv2.dtb"
XEN="xen"
DOM0_KERNEL="Image"
DOM0_RAMDISK="dom0-rootfs.cpio.gz"
XEN_CMD="console=dtuart dom0_mem=512M"

NUM_DOMUS=1
DOMU_KERNEL[0]="Image"
DOMU_RAMDISK[0]="initrd"
DOMU_MEM[0]="256"

LOAD_CMD="tftpb"
UBOOT_SOURCE="boot.source"
UBOOT_SCRIPT="boot.scr"' > binaries/config

if [[ "${test_variant}" == "static-mem" ]]; then
    echo -e "\nDOMU_STATIC_MEM[0]=\"0x${domu_base} 0x${domu_size}\"" >> binaries/config
fi

if [[ "${test_variant}" == "boot-cpupools" ]]; then
    echo '
CPUPOOL[0]="cpu@1 null"
DOMU_CPUPOOL[0]=0
NUM_CPUPOOLS=1' >> binaries/config
fi

rm -rf imagebuilder
git clone https://gitlab.com/ViryaOS/imagebuilder
bash imagebuilder/scripts/uboot-script-gen -t tftp -d binaries/ -c binaries/config


# Run the test
rm -f smoke.serial
set +e
echo "  virtio scan; dhcp; tftpb 0x40000000 boot.scr; source 0x40000000"| \
timeout -k 1 240 \
./binaries/qemu-system-aarch64 \
    -machine virtualization=true \
    -cpu cortex-a57 -machine type=virt \
    -m 1024 -monitor none -serial stdio \
    -smp 2 \
    -no-reboot \
    -device virtio-net-pci,netdev=n0 \
    -netdev user,id=n0,tftp=binaries \
    -bios /usr/lib/u-boot/qemu_arm64/u-boot.bin |& tee smoke.serial

set -e
(grep -q "^Welcome to Alpine Linux" smoke.serial && grep -q "${passed}" smoke.serial) || exit 1
exit 0
