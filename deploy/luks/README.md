# LUKS Full-Disk Encryption Setup Guide

This guide covers setting up LUKS encryption for the sniffer-rt probe's data
partition on a Raspberry Pi 5 with NVMe storage.

## Prerequisites

- Raspberry Pi 5 with NVMe SSD (via M.2 HAT)
- Raspberry Pi OS (Bookworm 64-bit)
- `cryptsetup` package installed

```bash
sudo apt install cryptsetup
```

## Creating the LUKS Partition

1. Identify the NVMe device (typically `/dev/nvme0n1`):

```bash
lsblk
```

2. Create a partition for encrypted data (assuming `/dev/nvme0n1p2`):

```bash
sudo fdisk /dev/nvme0n1
# Create a new partition (e.g., p2) for data storage
```

3. Format with LUKS:

```bash
sudo cryptsetup luksFormat /dev/nvme0n1p2
# You will be prompted for a passphrase
```

4. Open the encrypted volume:

```bash
sudo cryptsetup open /dev/nvme0n1p2 srt-data
```

5. Create filesystem:

```bash
sudo mkfs.ext4 /dev/mapper/srt-data
```

## Key File Creation and Enrollment

Using a key file allows automatic unlock without interactive passphrase entry.

1. Generate a key file:

```bash
sudo dd if=/dev/urandom of=/root/.luks-keyfile bs=4096 count=1
sudo chmod 400 /root/.luks-keyfile
```

2. Add the key file to the LUKS volume:

```bash
sudo cryptsetup luksAddKey /dev/nvme0n1p2 /root/.luks-keyfile
```

## USB Key Unlock Method

For air-gapped deployments, store the key on a USB stick:

1. Prepare the USB key:

```bash
# Format a small USB drive
sudo mkfs.ext4 /dev/sda1
sudo mount /dev/sda1 /mnt
sudo dd if=/dev/urandom of=/mnt/srt.key bs=4096 count=1
sudo chmod 400 /mnt/srt.key
sudo umount /mnt
```

2. Add the USB key to LUKS:

```bash
sudo mount /dev/sda1 /mnt
sudo cryptsetup luksAddKey /dev/nvme0n1p2 /mnt/srt.key
sudo umount /mnt
```

3. Configure initramfs to look for USB key on boot (add to `/etc/crypttab`):

```
srt-data /dev/nvme0n1p2 /dev/disk/by-label/SRT-KEY:/srt.key luks,keyscript=/lib/cryptsetup/scripts/passdev
```

## /etc/crypttab Configuration

Add the following line to `/etc/crypttab`:

```
srt-data  /dev/nvme0n1p2  /root/.luks-keyfile  luks
```

For UUID-based configuration (recommended):

```bash
# Get the UUID
sudo blkid /dev/nvme0n1p2
```

```
srt-data  UUID=<your-uuid-here>  /root/.luks-keyfile  luks
```

## Auto-mount in /etc/fstab

Add to `/etc/fstab`:

```
/dev/mapper/srt-data  /opt/sniffer/data  ext4  defaults,noatime  0  2
```

## Emergency Key Wipe Procedure

In the event of a tamper detection or compromise, the LUKS header can be
destroyed to render all data unrecoverable:

```bash
# DANGER: This permanently destroys all data on the volume
sudo cryptsetup erase /dev/nvme0n1p2

# Or overwrite the LUKS header entirely
sudo dd if=/dev/urandom of=/dev/nvme0n1p2 bs=1M count=16
```

The watchdog script (`scripts/watchdog.sh`) performs an automated version of
this when the tamper GPIO pin is triggered.

## Testing Encryption

1. Verify the volume is encrypted:

```bash
sudo cryptsetup luksDump /dev/nvme0n1p2
```

2. Test opening with key file:

```bash
sudo cryptsetup open --test-passphrase /dev/nvme0n1p2 --key-file /root/.luks-keyfile
echo $?  # Should return 0
```

3. Verify mount works:

```bash
sudo cryptsetup open /dev/nvme0n1p2 srt-data --key-file /root/.luks-keyfile
sudo mount /dev/mapper/srt-data /opt/sniffer/data
df -h /opt/sniffer/data
```

4. Test emergency wipe (on a TEST volume only):

```bash
sudo cryptsetup close srt-data
sudo cryptsetup erase /dev/nvme0n1p2
# Volume should now be inaccessible
```
