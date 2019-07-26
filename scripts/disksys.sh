#!/bin/bash

# permalink: https://gist.github.com/apla/d634b2d984b1fa4e1038bab28b1106ec

os_specific () {
	if [[ "$OSTYPE" == "linux-gnu" ]]; then
        # Linux

		local FN="${1}_linux"

	elif [[ "$OSTYPE" == "darwin"* ]]; then
		# macOS

		local FN="${1}_macos"

	else
		echo "System not supported"
		# Unknown
	fi

	$FN
}

setvar() {
	local varname default prompt
	varname=$1; prompt=$2; default=$3
	if read -r -e -p "$prompt" "$varname" && [[ $varname ]]; then
		return 0
	else
		printf -v "$varname" %s "$default"
	fi
}


reset_bus () {
	BUS=
	CONNECTOR=
	LINK_SPEED=
	LINK_WIDTH=
}

reset_drive () {
	PARTITION=
	MODEL=
	SERIAL=
	DEVICE=
	LINK_SPEED=
	LINK_LIMIT=
	LINK_WIDTH=
	SIZE=
	BAY=
}

PAINT_BOLD=$(tput bold)
PAINT_REV=$(tput rev)
PAINT_NORMAL=$(tput sgr0)

print_drive_info () {
	
	CONNECTION=$(echo $BUS $CONNECTOR $LINK_SPEED $LINK_WIDTH)

	if [ -t 1 ] ; then
		echo "${PAINT_BOLD}$DEVICE${PAINT_NORMAL} $PARTITION ${PAINT_BOLD}$SIZE${PAINT_NORMAL} ${PAINT_REV}$MODEL${PAINT_NORMAL} ($CONNECTION) $BAY"
	else
		echo "$DEVICE $PARTITION $SIZE $MODEL ($CONNECTION) $BAY"
	fi
}

print_drive_info_ () {
	echo "<$DEVICE> <$PARTITION> <$SIZE> <$MODEL> (<$BUS> <$CONNECTOR> <$LINK_SPEED> <$LINK_WIDTH>) $BAY"
}

print_partitions_macos () {
	local DEVICE=$1

	SAVEIFS=$IFS

	# HAVE_CONTAINER=

	# while read i; do echo $i; done < <(echo "$FILECONTENT")

	while IFS= read -r LINE ; do
		if [[ $LINE =~ Apple_APFS[[:space:]]+Container[[:space:]]+(disk[0-9]+) ]] ; then
			
			HAVE_CONTAINER=${BASH_REMATCH[1]}
		else
			HAVE_CONTAINER=
		fi

		echo "$LINE"
	done < <(diskutil list $DEVICE | tail -n+2)

	if [ "x$HAVE_CONTAINER" != "x" ] ; then
		while IFS= read -r LINE ; do
			if [[ $LINE =~ ^([[:space:]]+)([0-9]+):([[:space:]]+)(.*) ]] ; then
				echo "   ${BASH_REMATCH[1]}${BASH_REMATCH[2]}:${BASH_REMATCH[3]:3}${BASH_REMATCH[4]}"
			else
				echo "$LINE"
			fi

			
		done < <(diskutil list /dev/$HAVE_CONTAINER | tail -n+5)
		
	fi

}

parse_sata_version_string () {
	VAL=$@
	case $VAL in
		# macOS
		"1.5 Gigabit") LINK_SPEED="1.1" ;;
		"3 Gigabit")   LINK_SPEED="2.0" ;;
		"6 Gigabit")   LINK_SPEED="3.0" ;;
		# linux
		"1.5 Gbps") LINK_SPEED="1.1" ;;
		"3.0 Gbps") LINK_SPEED="2.0" ;;
		"6.0 Gbps") LINK_SPEED="3.0" ;;
	esac

}

parse_pcie_version_string () {
	VAL=$@
	case $VAL in
		# macOS
		"2.5 GT/s") LINK_SPEED="1.1" ;;
		"5.0 GT/s") LINK_SPEED="2.0" ;;
		"8.0 GT/s") LINK_SPEED="3.0" ;;
		# linux
		"2.5 GT/s") LINK_SPEED="1.1" ;;
		"5 GT/s") LINK_SPEED="2.0" ;;
		"8 GT/s") LINK_SPEED="3.0" ;;
	esac
}

collect_line_sys_profiler () {
	local KEY=$1
	local VAL=`echo $2`
	if [ "x$KEY" == "x" ] ; then
		if [ "x$DEVICE" != "x" ] ; then
			print_drive_info
			print_partitions_macos $DEVICE
			reset_drive
		fi
	elif [ "x$KEY" == "xNVMExpress" ] ; then
		reset_bus
		BUS="NVME"
	elif [ "x$KEY" == "xSATA/SATA Express" ] ; then
		reset_bus
		BUS="AHCI"
	elif [ "x$KEY" == "Serial-ATA" ] ; then
		reset_bus
		BUS="AHCI"
	elif [ "x$KEY" == "xUSB" ] ; then
		reset_bus
		BUS="USB"
		# CONNECTOR="3.0"
	elif [ "x$KEY" == "xThunderbolt" ] ; then
		reset_bus
		BUS="Thunderbolt"
	elif [ "x$KEY" == "xSpeed" ] ; then
		if [ "x$BUS" == "xUSB" ] ; then
			case $VAL in
				"Up to 12 Mb/sec")  LINK_SPEED="1.1" ;;
				"Up to 480 Mb/sec") LINK_SPEED="2.0" ;;
				"Up to 5 Gb/sec")   LINK_SPEED="3.0" ;;
				"Up to 10 Gb/sec")  LINK_SPEED="3.1" ;;
			esac
		elif [ "x$BUS" == "xThunderbolt" ] ; then
			case $VAL in
				# https://forums.macrumors.com/threads/5k-imac-thunderbolt-ports.1912874/
				"Up to 10 Gb/s x1") LINK_SPEED="1.0" ;;
				"Up to 10 Gb/s x2") LINK_SPEED="1.0" ;;
				"Up to 20 Gb/s x1") LINK_SPEED="2.0" ;;
				"Up to 40 Gb/s x1") LINK_SPEED="3.0" ;;
			esac
		fi
	elif [ "x$KEY" == "xPhysical Interconnect" ] ; then
		if [ $VAL == "PCI" ] ; then
			CONNECTOR="${VAL}e"
		else
			CONNECTOR="${VAL}"
		fi
	elif [ "x$KEY" == "xNegotiated Link Speed" ] ; then
		parse_sata_version_string "$VAL"
	elif [ "x$KEY" == "xLink Speed" ] ; then
		if [ "x$CONNECTOR" == "xPCIe" ] ; then
			parse_pcie_version_string "$VAL"
		elif [ "x$CONNECTOR" == "xSATA" ] ; then
			parse_sata_version_string "$VAL"
		fi
		# LINK_SPEED=$VAL
	elif [ "x$KEY" == "xLink Speed" ] ; then
		echo "&& negotiated link speed $KEY $VAL &&"
		LINK_LIMIT=$VAL
	elif [ "x$KEY" == "xLink Width" ] ; then
		LINK_WIDTH=$VAL
	elif [ "x$KEY" == "xBSD Name" ] ; then
		DEVICE=/dev/$VAL
		PARTITION_CONST=$(diskutil info $DEVICE | grep 'Content (IOContent)' | cut -d ':' -f 2 | xargs echo)
		case $PARTITION_CONST in
			"FDisk_partition_scheme") PARTITION="MBR" ;;
			"GUID_partition_scheme")  PARTITION="GPT" ;;
			"Apple_partition_scheme") PARTITION="APPLE" ;;
		esac
	elif [ "x$KEY" == "xSerial Number" ] ; then
		SERIAL=$VAL
	elif [ "x$KEY" == "xBay Name" ] ; then
		BAY="Bay #$VAL"
	elif [ "x$KEY" == "xCapacity" ] ; then
		SIZE=${VAL%(*}
		SIZE=$(echo $SIZE | tr -d ' ' | tr ',' '.')
	elif [ "x$KEY" == "xModel" ] ; then
		MODEL=$VAL
	elif [ "x$KEY" != "x" -a "x$KEY:" == "x$VAL" ] ; then
		MODEL=$KEY
	else
		X=2
		# echo "<<< $KEY => $VAL >>>"
	fi

	# echo $KEY "=>" $VAL

}

show_drives_macos () {
	system_profiler \
		SPSerialATADataType \
		SPUSBDataType \
		SPThunderboltDataType \
		SPNVMeDataType \
	-detailLevel mini | grep \
		-e '^SATA/SATA Express' \
		-e '^USB' \
		-e '^Thunderbolt:' \
		-e 'Capacity:' \
		-e 'BSD Name:' \
		-e 'Model:' \
		-e 'Revision:' \
		-e 'Serial Number:' \
		-e 'Bay Name:' \
		-e 'Physical Interconnect:' \
		-e 'Link Width:' \
		-e 'Link Speed:' \
		-e 'Speed:' \
		-e 'Rotational Rate:' \
		-e '^$' -e '.*:$' |\
	while read LINE ; do
		#echo ">>>" $LINE
		collect_line_sys_profiler "${LINE%:*}" "${LINE#*: }"
	done

	

}

get_device_usb_speed_linux () {
	# sudo lspci -vv -d ::0108 | less # look for nvme devices using PCI class ID
	DEV=$1
	DEVICE=/dev/$2
	SIZE=${3}B

	shift
	shift
	shift

	MODEL=$@

	BUS="USB"
	DEV_PATH=/sys/bus/usb/devices/$DEV
	USB_SPEED=`cat $DEV_PATH/speed`
	case $USB_SPEED in
		"1.5")   LINK_SPEED="1.0" ;;
		"12")    LINK_SPEED="1.1" ;;
		"480")   LINK_SPEED="2.0" ;;
		"5000")  LINK_SPEED="3.0" ;;
		"10000") LINK_SPEED="3.1" ;;
	esac

	SERIAL=`cat $DEV_PATH/serial | xargs echo`
}


get_device_nvme_speed_linux () {
	# sudo lspci -vv -d ::0108 | less # look for nvme devices using PCI class ID
	DEV=$1
	DEVICE=/dev/$2
	SIZE=${3}B

	BUS="NVME"
	CONNECTOR="PCIe"
	DEV_PATH=/sys/class/nvme/$DEV
	LINK_LIMIT=`cat $DEV_PATH/device/max_link_speed`
	LINK_MAX_WIDTH=`cat $DEV_PATH/device/max_link_width`
	# LINK_SPEED=`cat $DEV_PATH/device/current_link_speed`
	parse_pcie_version_string `cat $DEV_PATH/device/current_link_speed`
	LINK_WIDTH="x$(cat $DEV_PATH/device/current_link_width)"

	MODEL=`cat $DEV_PATH/model | xargs echo`
	SERIAL=`cat $DEV_PATH/serial | xargs echo`
	FW=`cat $DEV_PATH/firmware_rev`
}

get_device_sata_speed_linux () {
	DEV=$1
	SIZE=${2}B

	# for non-ata devices
	DEVICE=/dev/$DEV
	shift
	shift

	MODEL="$@"

	DEV_SYS_PATH=$(echo /sys/class/ata_port/ata*/../../host*/target*/*/block/$DEV)
	# echo "<<## DEV SYS PATH $DEV_SYS_PATH ##>>"
	LINK_NUM_START=${DEV_SYS_PATH//*ata_port\/ata/}
	LINK_NUM=${LINK_NUM_START///*}
	if [ "$LINK_NUM" != "*" ] ; then
		LINK_PATH=/sys/class/ata_link/link${LINK_NUM}
		parse_sata_version_string $(cat $LINK_PATH/sata_spd)
		if [ "x$LINK_SPEED" != "x" ] ; then
			CONNECTOR="SATA"
		fi
		LINK_LIMIT=`cat $LINK_PATH/sata_spd_limit`
		if [ "x$LINK_LIMIT" == "x<unknown>" ] ; then
			LINK_LIMIT=
		fi

		SAVEIFS=$IFS
		IFS=$'\t'
		# ATA IDENTIFY DEVICE
		# Words 10-19 Serial Number
		# Words 23-26 Firmware revision
		# Words 27-46 Model Number
		# Word 168 0: unknown 1: 5.25 2: 3.5 3: 2.5, 4: 1.8, 5: less than 1.8
		# Word 217 1 - ssd, >0401 - rpm
		ATA_INFO=(`cat $LINK_PATH/device/dev*/ata_device/dev*/id | tr -d '\n' | tr -d ' ' | perl -nE 's/([0-9a-f]{2})/chr hex $1/gie; say join "\t", substr ($_, 54, 40), substr ($_, 20, 20), substr ($_, 46, 8), qw(unknown 5.25 3.5 2.5 1.8 <1.8)[unpack ("n", substr ($_, 336, 2))], unpack ("n", substr ($_, 434, 2))' | tr -d ' '`)
		IFS=$SAVEIFS

		if [ "x$CONNECTOR" == "x" ] ; then
			CONNECTOR="ATA"
		fi

		MODEL=${ATA_INFO[0]}
		SERIAL=${ATA_INFO[1]}
		FW=${ATA_INFO[2]}
		PHYSICAL_SIZE=${ATA_INFO[3]}
		RPM=${ATA_INFO[4]}
	fi

}

get_negotiated_speed_linux () {
  for i in `grep -l Gbps /sys/class/ata_link/*/sata_spd`; do
	LINK_NUM=${i//[^0-9]/}
    echo Link "${i%/*}" Speed `cat $i` Max `cat ${i%/*}/sata_spd_limit`
	DEV_SYS_PATH=$(echo /sys/class/ata_port/ata${LINK_NUM}/../../host*/target*/*/block/s*)
	DEV_PATH=${DEV_SYS_PATH##*/}
	echo -n /dev/$DEV_PATH
    cat "${i%/*}"/device/dev*/ata_device/dev*/id | tr -d '\n' | tr -d ' ' | perl -nE 's/([0-9a-f]{2})/chr hex $1/gie; say join "\t", substr ($_, 54, 40), substr ($_, 20, 20), substr ($_, 46, 8), qw(unknown 5.25 3.5 2.5 1.8 <1.8)[unpack ('n', substr ($_, 336, 2))], unpack ('n', substr ($_, 434, 2))'
  done
}

show_drives_linux () {

	SAVEIFS=$IFS
	# parted --list
	# sudo lsblk -o name,mountpoint,fstype,partlabel,label,size,uuid
	lsblk -o name,mountpoint,fstype,partlabel,label,size,model |\
	while IFS= read -r LINE ; do

		# TODO: use udevadm info /dev/sda
		
		UDEV_PATH=
		if [[ $LINE =~ ^[a-z] ]] ; then
			UDEV_PATH=$(udevadm info -q path -n $LINE) # seems like udevadm ignores garbage at end
		fi

		reset_bus
		reset_drive
		# usually no empty lines
		if [[ $LINE =~ ^nvme[0-9]+ ]] ; then
			get_device_nvme_speed_linux ${BASH_REMATCH[0]} $LINE
		elif [[ $UDEV_PATH =~ usb[0-9]+/([^/]+)/ ]] ; then
			get_device_usb_speed_linux ${BASH_REMATCH[1]} $LINE
		elif [[ $UDEV_PATH =~ ata[0-9]+/([^/]+)/ ]] ; then
			get_device_sata_speed_linux $LINE
		else
			echo "$LINE"
		fi

		if [ "x$DEVICE" != "x" ] ; then
			# PARTITION=$(sudo blkid -o value -s PTTYPE $DEVICE | tr [a-z] [A-Z])
			PARTITION=$(udevadm info $DEVICE | grep ID_PART_TABLE_TYPE | cut -d = -f 2 | tr [a-z] [A-Z])
			print_drive_info
		fi
	done
	IFS=$SAVEIFS

	# cat /sys/class/ata_link/link1/device/dev1.0/ata_device/dev1.0/id | tr -d '\n' | tr -d ' ' | perl -nE 's/([0-9a-f]{2})/chr hex $1/gie; say join "\t", substr ($_, 54, 40), substr ($_, 20, 20), substr ($_, 46, 8), qw(unknown 5.25 3.5 2.5 1.8 <1.8)[unpack ('n', substr ($_, 336, 2))], unpack ('n', substr ($_, 434, 2))'
}

list_drives_linux () {
	DISKS=( $(lsblk --nodeps -n -o name) )
}

# TODO: maybe collect at show?
list_drives_macos () {
	# we need physical disks, synthesized and virtual (raid)
	DISKS=( $(diskutil list | grep -e '^/dev/' | cut -d '/' -f 3 | cut -d ' ' -f 1) )
}

collect_clone_options () {

	setvar FROM "Source disk (default: ${DISKS[0]}):" ${DISKS[0]}
	setvar TO   "Destination disk (default: ${DISKS[1]}):" ${DISKS[1]}

	#read -e -p "Source disk: " -i ${DISKS[0]} FROM
	#read -e -p "Destination disk: " -i ${DISKS[1]} TO

	exit 1

	if [ "x$FROM" == "x$TO" ] || [[ ! " ${DISKS[@]} " =~ " ${FROM} " ]] || [[ ! " ${DISKS[@]} " =~ " ${TO} " ]]
	then
		echo "Error occured: source and destination can't be the same device, device must be plugged in"

		exit 1
	fi

	read -p "Now I will copy partition information and data /dev/$FROM to /dev/$TO. All data on the /dev/${TO} will be erased! Type Y (or y) to proceed: " -n 1 -r

	if [[ ! $REPLY =~ ^[Yy]$ ]] ; then

		exit 0

	fi

	#echo    # (optional) move to a new line


}

perform_clone_macos () {

	# https://www.belightsoft.com/products/resources/apfs-bootable-clone-with-command-line

	PART_COUNT=1
	PART_FS="HFS+"
	PART_LABEL=$(uuidgen | cut -d '-' -f 1)
	PART_SIZE=R

	echo diskutil partitionDisk /dev/$TO $PART_COUNT GPT $PART_FS $PART_LABEL $PART_SIZE

	# create APFS container
	# diskutil apfs createContainer /dev/disk2s2
	# add APFS container
	# diskutil apfs addVolume disk2s2 APFS newAPFS

	TO_APFS_SLICE=$(diskutil list /dev/$TO | grep Apple_HFS | xargs echo | cut -d ' ' -f 6)

	echo diskutil apfs convert /dev/$TO_APFS_SLICE

	echo sudo vsdbutil -a /Volumes/$PART_LABEL

	TO_APFS_DISK=$(diskutil list /dev/$TO | grep -e Apple_APFS | xargs echo | cut -d ' ' -f 4)

	OS_VER=$(sw_vers -productVersion)
	RSYNC_VER=$(rsync --version | head -n 1 | tr -s ' ' | cut -d ' ' -f 3)

	if [ "${OS_VER:0:5}" == "10.14" ] ; then
		# 10.14
		echo sudo rsync -xrlptgoXvHS --progress --delete --fileflags / /Volumes/$PART_LABEL
	else
		# 10.13
		echo sudo rsync -xrlptgoEvHS --progress --delete / /Volumes/$PART_LABEL
	fi

	diskutil apfs addVolume /dev/$TO_APFS_DISK apfs Preboot -role B

	TO_APFS_PREBOOT=$(diskutil list /dev/$TO_APFS_DISK | grep -e Preboot | xargs echo | cut -d ' ' -f 7)

	diskutil mountVolume /dev/$TO_APFS_PREBOOT

	TO_PREBOOT_UUID=$(diskutil info /dev/$TO_APFS_PREBOOT | grep "Volume UUID" | xargs echo | cut -d ' ' -f 3)
	TO_PREBOOT_MOUNT_STR=$(diskutil info /dev/$TO_APFS_PREBOOT | grep "Mount Point")
	if [[ $TO_PREBOOT_MOUNT_STR =~ :[[:space:]]+(.*) ]] ; then
		TO_PREBOOT_MOUNT=${BASH_REMATCH[1]}
	fi

	mkdir $TO_PREBOOT_MOUNT/$TO_PREBOOT_UUID

	FROM_APFS_PREBOOT=$(diskutil list /dev/$FROM_APFS_DISK | grep -e Preboot | xargs echo | cut -d ' ' -f 7)

	diskutil mountVolume /dev/$FROM_APFS_PREBOOT

	FROM_PREBOOT_UUID=$(diskutil info /dev/$FROM_APFS_PREBOOT | grep "Volume UUID" | xargs echo | cut -d ' ' -f 3)
	FROM_PREBOOT_MOUNT_STR=$(diskutil info /dev/$FROM_APFS_PREBOOT | grep "Mount Point")
	if [[ $FROM_PREBOOT_MOUNT_STR =~ :[[:space:]]+(.*) ]] ; then
		FROM_PREBOOT_MOUNT=${BASH_REMATCH[1]}
	fi

	sudo rsync -xrlptgoEvHS --progress --delete $FROM_PREBOOT_MOUNT/$FROM_PREBOOT_UUID/ $TO_PREBOOT_MOUNT/$TO_PREBOOT_UUID/

	diskutil apfs updatePreboot /dev/$TO_APFS_PREBOOT

	sudo bless --folder /Volumes/$PART_LABEL/System/Library/CoreServices --bootefi

	sudo update_dyld_shared_cache -root /Volumes/$PART_LABEL -force
}

perform_clone_linux () {

	if [ "x$NO_PART" == "x" ] ; then

		# partition?

		# GPT
		# sudo parted /dev/$TO mklabel gpt

		# MBR
		sudo parted /dev/$TO mklabel msdos

		# Create the New Partition

		# Once the format is selected, you can create a partition spanning the entire drive by typing:

		# sudo parted -a opt /dev/$TO mkpart primary ext4 0% 100%

		# https://askubuntu.com/questions/8819/unmounting-several-partitions-at-once
		TO_PARTS=$(ls /dev/$TO?*)

		if [ $? -eq 0 ] ; then
			for TO_PART in $TO_PARTS ; do
				umount -l $TO_PART
			done
		fi
		# sleep a little?

		sleep 5

		sfdisk -d /dev/${FROM} > part_table
		sfdisk /dev/${TO} < part_table

		sleep 5

		# sleep a little more
		sudo partprobe /dev/${TO}

	fi

	FROM_UUID=`lsblk -nr -o UUID,MOUNTPOINT | grep -Po '.*(?= /$)'`
	FROM_SWAP_UUID=`lsblk -nr -o UUID,MOUNTPOINT | grep -Po '.*(?= \[SWAP\]$)'`

	# find a target partition
	TO_LINUX_PART=$(sudo fdisk -l /dev/${TO} | grep Linux | head -n 1 | cut -d ' ' -f 1)
	TO_SWAP_PART=$(sudo fdisk -l /dev/${TO} | grep swap | head -n 1 | cut -d ' ' -f 1)


	if [ "x$NO_FORMAT" == "x" ] ; then


		# exit 1

		sudo mkfs.ext4 ${TO_LINUX_PART}
		sudo mkswap ${TO_SWAP_PART}
		#sudo mkfs.ext4 -L datapartition ${TO_LINUX_PART}
		# sudo e2label ${TO_LINUX_PART} system


		#echo "FROM_UUID $FROM_UUID"
		#echo "FROM_SWAP_UUID $FROM_SWAP_UUID"

	fi

	TO_UUID=`lsblk -nr -o UUID $TO_LINUX_PART`
	TO_SWAP_UUID=`lsblk -nr -o UUID $TO_SWAP_PART`

	echo "LINUX $FROM ($FROM_UUID) => $TO#$TO_LINUX_PART ($TO_UUID)"
	echo "SWAP $FROM ($FROM_SWAP_UUID) => $TO#$TO_SWAP_PART ($TO_SWAP_UUID)"
	#	echo "TO: LINUX $TO_LINUX_PART, SWAP $TO_SWAP_PART"

	TO_MOUNT_DIR=/media/backup

	if [ "x$NO_COPY" == "x" ] ; then
		sudo mkdir $TO_MOUNT_DIR
		sudo mount -t ext4 $TO_LINUX_PART $TO_MOUNT_DIR

		sudo grub-install --boot-directory=$TO_MOUNT_DIR/boot /dev/$TO

		rsync -avxHAXW --progress / $TO_MOUNT_DIR/

		sed -i -- "s/${FROM_UUID}/$TO_UUID/g" $TO_MOUNT_DIR/etc/fstab
		sed -i -- "s/${FROM_SWAP_UUID}/$TO_SWAP_UUID/g" $TO_MOUNT_DIR/etc/fstab

		sed -i -- "s/${FROM_UUID}/$TO_UUID/g" $TO_MOUNT_DIR/boot/grub/grub.cfg
		sed -i -- "s/${FROM_SWAP_UUID}/$TO_SWAP_UUID/g" $TO_MOUNT_DIR/boot/grub/grub.cfg

		sed -i -- "s/${FROM_UUID}/$TO_UUID/g" $TO_MOUNT_DIR/boot/grub/i386-pc/load.cfg
		sed -i -- "s/${FROM_SWAP_UUID}/$TO_SWAP_UUID/g" $TO_MOUNT_DIR/boot/grub/i386-pc/load.cfg

	fi

	if [ "x$SET_HOSTNAME" != "x" ] ; then
		
		sed -i -- "s/${HOSTNAME}/$SET_HOSTNAME/g" $TO_MOUNT_DIR/etc/hostname
		sed -i -- "s/${HOSTNAME}/$SET_HOSTNAME/g" $TO_MOUNT_DIR/etc/hosts
		sed -i -- "s/${HOSTNAME}/$SET_HOSTNAME/g" $TO_MOUNT_DIR/etc/sysconfig/network
	fi

	# UEFI ?
	# efibootmgr -c -L "Archlinux (debug)" -l '\EFI\archlinux\vmlinuz-linux' -u "root=/dev/mapper/vg1-lvroot rw initrd=\EFI\archlinux\initramfs-linux.img systemd.log_level=debug systemd.log_target=kmsg log_buf_len=1M enforcing=0"
}

CMD=$1

case $CMD in
	clone)
		os_specific show_drives

		os_specific list_drives

		# TODO: check for disk count > 1
		collect_clone_options

		os_specific perform_clone
		;;
	*)
		os_specific show_drives
		;;
esac
