IMG_FILE="/tmp/my_usb_storage.img"
CONFIGFS="/sys/kernel/config"

#modprobe libcomposite
#mount none "$CONFIGFS" -t configfs

if ! [ -f "$IMG_FILE" ]; then
	dd if=/dev/zero bs=1024 count=10000 of="$IMG_FILE"
fi

if ! [ -d "$CONFIGFS"/usb_gadget ]; then
	echo "configfs not load" && exit 1
fi

cd "$CONFIGFS"/usb_gadget/

if [ -d g1 ]; then
	echo "$CONFIGFS/usb_gadget/g1 already exist"
	read -p "preess any key to remove them..." confirm
	echo "" > g1/UDC
	rm -rf g1/configfs/c.1/mass_storage.0
	rm -rf g1/configs/c.1/strings/0x409
	rm -rf g1/configs/c.1
	rm -rf g1/functions/mass_storage.0
	rm -rf g1/strings/0x409
	rm -rf g1
fi
if [ -d g1 ]; then
	echo "remove failed" && exit 1
fi

#-------------------------- start config --------------------
mkdir g1
cd g1

mkdir configs/c.1
mkdir functions/mass_storage.0 && sleep 1
echo "$IMG_FILE" > functions/mass_storage.0/lun.0/file

mkdir strings/0x409
mkdir configs/c.1/strings/0x409

echo 0x8888 > idProduct
echo 0x6666 > idVendor
echo "1234567890" > strings/0x409/serialnumber
echo "RuFeng" > strings/0x409/manufacturer
echo "Mass Storage Gadget" > strings/0x409/product

echo "Conf 1" > configs/c.1/strings/0x409/configuration
echo 120 > configs/c.1/MaxPower
ln -s functions/mass_storage.0 configs/c.1

echo "dummy_udc.0" > UDC

# echo connect > /sys/class/udc/dummy_udc.0/soft_connect
# echo disconnect > /sys/class/udc/dummy_udc.0/soft_connect
