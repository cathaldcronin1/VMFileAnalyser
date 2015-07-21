# -*- coding: utf-8 -*-
# Disk Analyser Tool For EE6012- Data Forensics
# Author: Cathal Cronin
# Date: 03/03/2015
# Version: 1.0


# Used hurry.filesize to convert bytes to a nice format.
# Used binascii to work with hex strings and hex conversion.
# Used sys to handle parameter passing when running tool.
from hurry.filesize import size
import binascii
import sys

# Map the bytes to system type
part_types = {"00": "Unknown or Empty",
              "01": "12-bit FAT",
              "04": "16-bit FAT (< 32MB)",
              "05": "Extended MS-DOS Partition",
              "06": "FAT-16 (32MB to 2GB)",
              "07": "NTFS",
              "0B": "FAT-32 (CHS)",
              "0C": "FAT-32 (LBA)",
              "0E": "FAT-16 (LBA)"}

# Constant for sector size of 512 Bytes
SECTOR_SIZE = 512

# First sector of an NTFS Volume's boot sector has a jump instruction and OEM ID
# These are 3 and 8 bytes respectively. This constant offsets it
# for when I seek into the disk.
VOL_OFFSET = 0

class DiskAnalyser():
    def __init__(self, filepath):
        self.filepath = filepath

    def read_disk_info(self, address, reading_partition=True, reading_volume=False):
        """ Read into the disk and return bytes of information """

        disk_info = ""
        seek_address = int(address)
        read_range = 0

        if reading_partition:
            # if reading a partition just seek to address.
            seek_address = address
            # Partition table entries are 16 bytes
            read_range = 16
        else:
            # if reading volume info multiply address by sector size
            seek_address = address * SECTOR_SIZE + VOL_OFFSET
            print "Seek address", seek_address


            # NTFS Volume information is within in the BPB and extended BPB fields.
            read_range = 73

        with open(self.filepath, "rb") as f:
            # seek to sector address
            f.seek(seek_address)

            # read bytes and convert to hex
            byte = f.read(read_range)
            disk_info = binascii.hexlify(byte).upper()

        return disk_info

    def toBigEndian(self, hexString):
        """ Convert hexString to Big-Endian Format """
        swappedBytes = ""
        chunk = ""
        lastpos = 0
        for c in xrange(0, len(hexString) + 2, 2):
            # Take byte chunk
            chunk = hexString[lastpos:c]
            # Move to end of string
            swappedBytes = chunk + swappedBytes
            lastpos = c
        return swappedBytes

    def get_partition_type(self, p_type):
        """ Return partition type """
        for t in part_types:
            if t in part_types.keys():
                return part_types[p_type]

    def get_partition_info(self):
        """ Pick out relevant partition information """
        # first partition is at 0x1BE, convert this to decimal value
        # seek that amount into the file, read the 16 bytes
        # and that is the MBR record for the partition
        # 0x1CE -> 446 - 1st partition
        # 0x1BE -> 462 - 2nd partition
        # 0x1DE -> 478 - 3rd partition
        # 0x1FE -> 494 - 4th partition

        partitions = [446, 462, 478, 494]
        partition_info = []

        p_no = 1
        p_info = []
        p_flag = ""
        p_type = ""
        p_start_addr = ""
        p_size = ""

        # For each VISIBLE partition, pull out required information
        for p in partitions:
            # get partition information
            part_info = self.read_disk_info(p,True,False)

            # get flag, type, start sector address and size in hex
            p_flag = self.toBigEndian(part_info[:2] + '0x')
            p_type = self.toBigEndian(part_info[8:10] + '0x')
            p_start_addr = self.toBigEndian(part_info[16:24] + '0x')
            p_size = self.toBigEndian(part_info[24:34] + '0x')


            # above variables formatted for nice output later
            p_type_str = "(" + self.get_partition_type(part_info[8:10]) + ")"
            p_start_addr_str = "(" + str(int(self.toBigEndian(part_info[16:24]), 16)) + ")"
            p_size_str = "(" + str(int(self.toBigEndian(part_info[24:34]), 16)) + ")"

            # if the partition type is 0x00, it is unassigned
            # Don't add to list of visible partitions, otherwise do
            if p_type != "0x00":
              p_info.append({"Partition #": p_no,
                             "Flag": p_flag,
                             "Type": p_type,
                             "Sector Start Address": p_start_addr,
                             "Flag_str": p_flag,
                             "Type_str": p_type_str,
                             "Sector Start Address_str": p_start_addr_str,
                             "Partition Size": p_size,
                             "Partition Size_str": p_size_str, })
            p_no += 1


        return p_info

    def get_NTFS_vol_info(self, address):
        """ Get Information NTFS Volume"""

        # Get NTFS BPB and Extended BPB code.
        vol_info = self.read_disk_info(address, False, True)
        print len(vol_info)

        # This also appears to work! but there was a minus sign beside some of the hex values.
        # After taking these out it seemed to fix this.
        # Got that hex example from -> ntfs.com/ntfs-partition-boot-sector.htm
        # vol_info = "EB52904E5446532020202000020800000000000000F800003F00FF003F00000000000000800080004AF57F0000000000040000000000000054FF070000000000F60000000100000014A51B74C91B741C00000000"

        # This one works also!
        # Got that hex example from -> http://www.cse.scu.edu/~tschwarz/coen252_07Fall/Lectures/NTFS.html
        # vol_info = "EB52904E5446532020202000020800000000000000F800003F00FF00C53901000000000080008000F7AF4E0900000000E97F0C00000000009D02400000000000F600000001000000FE74AC888FAC889000000000"

        # Pull out information on NTFS Volume.

        bytes_per_sector = int(self.toBigEndian(vol_info[22:26]), 16)

        sectors_per_cluster = int(self.toBigEndian(vol_info[26:28]), 16)

        media_descriptor = int(self.toBigEndian(vol_info[42:44]), 16)

        total_sectors = int(self.toBigEndian(vol_info[80:94].strip("0")), 16)

        MFT_cluster_location = int(self.toBigEndian(vol_info[96:110].strip("0")), 16)

        # NOTE HAD TO STRIP ZEROS FROM THIS READING WOULDN'T WORK OTHERWISE
        # TODO: LOOK INTO!!!

        MFT_copy_cluster_location = int(self.toBigEndian(vol_info[112:126].strip("0")), 16)

        clusters_per_MFT_record = int(self.toBigEndian(vol_info[128:130]), 16)

        clusters_per_index_buffer = int(self.toBigEndian(vol_info[136:138]), 16)

        volume_serial_number = vol_info[144:160]




        print  "bytes_per_sector: ",  bytes_per_sector
        print  "sectors_per_cluster: ",  sectors_per_cluster
        print  "media_descriptor: ",  media_descriptor
        print  "total_sectors: ",  total_sectors
        print  "MFT_cluster_location: ",  MFT_cluster_location
        print  "MFT_copy_cluster_location: ",  MFT_copy_cluster_location
        print  "clusters_per_MFT_record: ",  clusters_per_MFT_record
        print  "clusters_per_index_buffer: ",  clusters_per_index_buffer
        print  "volume_serial_number: ",  volume_serial_number




    def get_volume_info(self, address):
        """ Pick out relevant volume information """

        vol_info = self.read_disk_info(address,False, True)

        # Reserved Area size in Sectors
        # 0Eh - 2 bytes
        reserved_area_size = int(self.toBigEndian(vol_info[-36:-32]), 16)

        # FAT size in Sectors
        # 16h, 17h  - 1 word
        fat_size = int(self.toBigEndian(vol_info[-20:-16]), 16)

        # No. of FATs
        # 10h - 1 byte
        num_fats = int(self.toBigEndian(vol_info[-32:-30]), 16)

        # FAT Area = (No. of FATs * FAT size in sectors)
        fat_area_size =  fat_size * num_fats

        # No. of root dir entries
        # 11h - 1 word
        num_root_dirs = int(self.toBigEndian(vol_info[-30:-26]),16)

        # always 32 bytes for a FAT volume
        dir_entry_size = 32

        # Root dir size in sectors
        root_dir_size = (num_root_dirs * dir_entry_size) / SECTOR_SIZE

        # No. of sectors per cluster
        # 0D - 1 byte
        num_sectors = int(self.toBigEndian(vol_info[-38: -36]),16)

        DA_address = address + reserved_area_size + fat_area_size
        cluster_2_addr = DA_address + root_dir_size

        return {"num_sectors": num_sectors,
                "size_of_FAT": fat_area_size,
                "root_dir_size": root_dir_size,
                "No of Root Dirs entries": num_root_dirs,
                "cluster_2_addr": cluster_2_addr,
                "DA_address": DA_address}

    def get_del_file_info(self, root_dir_address, first_cluster, root_dir_size):
        """ Retrieve information for the first deleted file in the root directory"""
        file_name = ""
        file_size = 0
        start_cluster = 0
        count = 0
        found_deleted = False

        # create address of sector we need to seek to
        sector_address = root_dir_address * SECTOR_SIZE

        with open(self.filepath, "rb") as f:
            # Seek to file directory address
            f.seek(sector_address)

            # Keep reading files until we find one which was deleted
            while found_deleted != True:

                # read 32 bytes of directory entry
                byte = f.read(32)

                # if a deleted file, get file info
                if binascii.hexlify(byte).upper()[:2] == "E5":
                    found_deleted = True
                    file_name = binascii.hexlify(byte).upper()[:22].decode("hex")
                    start_cluster = self.toBigEndian(binascii.hexlify(byte[-6:-4])).upper()
                    file_size = int(self.toBigEndian(binascii.hexlify(byte[-4:])).upper(), 16)

                count += 1

                # If we've checked all files within in root directory,
                # exit loop and display no deleted file information
                if count >= root_dir_size:
                    return {"File_Name": "No Deleted Files - No Name",
                            "File_Size": "No Deleted Files - No Size",
                            "Cluster_Address": "No Deleted Files - No Cluster Address",
                            "File_Data": "No Deleted Files - No File Data"}

            # Calculate cluster sector address
            file_cluster_addr = int(int(first_cluster) + ((int(start_cluster,16) - 2) * 8))

            # Seek to deleted file on disk
            f.seek(file_cluster_addr * SECTOR_SIZE)

            # read 16 bytes of information
            file_data = f.read(16)
            if file_data == "":
                file_data = "No Deleted Files - No File Data"

            return {"File_Name": file_name,
                    "File_Size": size(file_size),
                    "Cluster_Address": start_cluster + "h or " + str(int(start_cluster,16)) + "d",
                    "File_Data": file_data}

def main(argv):
    if len(argv) == 2:
        file_path = argv[1]
    else:
        # Display how to use if you don't give a file path
        print "Usage: python diskAnalyser.py <path_to_file>"
        sys.exit()

    # Create diskAnalyser object, with a file path
    disk_analyser = DiskAnalyser(file_path)

    # Get partition information from MBR (Master Boot Record)

    p_info = disk_analyser.get_partition_info()

    print "----- PARTITION INFO -----"
    print "Number of Visible Partitions:", len(p_info)

    for p in p_info:
        print "Partition #", p.get("Partition #")
        print "Start Sector Address:", p.get("Sector Start Address"), p.get("Sector Start Address_str")
        print "Partition Size:", int(p.get("Partition Size"),16),"Sectors",
        print "OR Approximately", size(int(p.get("Partition Size"),16) * SECTOR_SIZE)
        print "File System Type:", p.get("Type"), p.get("Type_str")
        print


    # Get NTFS volume address in decimal
    vol_sec_address = int(p_info[0].get("Sector Start Address"),16)

    print "----- VOLUME INFO -----"


    NTFS_vol_info = disk_analyser.get_NTFS_vol_info(vol_sec_address)


if __name__ == '__main__':
    main(sys.argv)
