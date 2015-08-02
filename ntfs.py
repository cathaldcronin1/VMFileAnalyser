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

from sets import Set

import mftutils

# Map the bytes to system type
PART_TYPES = {"00": "Unknown or Empty",
              "01": "12-bit FAT",
              "04": "16-bit FAT (< 32MB)",
              "05": "Extended MS-DOS Partition",
              "06": "FAT-16 (32MB to 2GB)",
              "07": "NTFS",
              "0B": "FAT-32 (CHS)",
              "0C": "FAT-32 (LBA)",
              "0E": "FAT-16 (LBA)"}


ATTRIBUTE_TYPES = {"10000000": "$STANDARD_INFORMATION",
                   "20000000": "$ATTRIBUTE_LIST",
                   "30000000": "$FILE_NAME",
                   "40000000": "$VOLUME_VERSION",
                   "40000000": "$OBJECT_ID",
                   "50000000": "$SECURITY_DESCRIPTOR",
                   "60000000": "$VOLUME_NAME",
                   "70000000": "$VOLUME_INFORMATION",
                   "80000000": "$DATA",
                   "90000000": "$INDEX_ROOT",
                   "A0000000": "$INDEX_ALLOCATION",
                   "B0000000": "$BITMAP",
                   "C0000000": "$SYMBOLIC_LINK",
                   "C0000000": "$REPARSE_POINT",
                   "D0000000": "$EA_INFORMATION",
                   "E0000000": "$EA",
                   "F0000000": "$PROPERTY_SET",
                   "100000000": "$LOGGED_UTILITY_STREAM"}

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
            seek_address = address * SECTOR_SIZE
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

    def get_disk_info(self, address, bytes_to_read):

        with open(self.filepath, "rb") as f:
            # seek to sector address
            f.seek(address)

            # read bytes and convert to hex
            byte = f.read(bytes_to_read)
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
        for t in PART_TYPES:
            if t in PART_TYPES.keys():
                return PART_TYPES[p_type]


    def get_attribute_type(self, attr_types):
        """ Return partition type """
        for t in ATTRIBUTE_TYPES:
            if t in ATTRIBUTE_TYPES.keys():
                return ATTRIBUTE_TYPES[attr_types]

    def filetime_to_Millis(self, filetime):

        filetime -= 116444736000000000L
        if filetime < 0:
            filetime = -1 - ((-filetime - 1) / 10000)
        else:
            filetime = filetime / 10000

        return filetime

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
        print vol_info
        print

        # This also appears to work! but there was a minus sign beside some of the hex values.
        # After taking these out it seemed to fix this.
        # Got that hex example from -> ntfs.com/ntfs-partition-boot-sector.htm
        # vol_info = "EB52904E5446532020202000020800000000000000F800003F00FF003F00000000000000800080004AF57F0000000000040000000000000054FF070000000000F60000000100000014A51B74C91B741C00000000"

        # This one works also!
        # Got that hex example from -> http://www.cse.scu.edu/~tschwarz/coen252_07Fall/Lectures/NTFS.html
        # vol_info = "EB52904E5446532020202000020800000000000000F800003F00FF00C53901000000000080008000F7AF4E0900000000E97F0C00000000009D02400000000000F600000001000000FE74AC888FAC889000000000"

        # Pull out information on NTFS Volume.

        # vol_info = "EB52904E5446532020202000020800000000000000F800003F00FF00002803000000000080008000FFCF3C010000000000000C00000000000200000000000000F600000001000000497AA398B1A3982A00000000"

        bytes_per_sector = int(self.toBigEndian(vol_info[22:26]), 16)

        sectors_per_cluster = int(self.toBigEndian(vol_info[26:28]), 16)

        media_descriptor = int(self.toBigEndian(vol_info[42:44]), 16)

        total_sectors = int(self.toBigEndian(vol_info[80:94]), 16)

        MFT_cluster_location = int(self.toBigEndian(vol_info[96:110]), 16)

        # NOTE HAD TO STRIP ZEROS FROM THIS READING WOULDN'T WORK OTHERWISE
        # TODO: LOOK INTO!!!

        MFT_copy_cluster_location = int(self.toBigEndian(vol_info[112:126]), 16)

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

        ntfs_vol_info = {"bytes_per_sector" : bytes_per_sector,
                         "sectors_per_cluster" : sectors_per_cluster,
                         "MFT_cluster_location" : MFT_cluster_location}

        return ntfs_vol_info



    def get_MFT_info(self, address):

        for i in range(1):

            mft_record = self.get_disk_info(address, 1024)
            print "MFT File Record: ", i
            print
            print

            print "magic number:",                          mft_record[0:8].decode("hex")
            if mft_record[0:8].decode("hex") != "FILE":
                # terminate
                return
            print "update sequence offset:",                int(self.toBigEndian(mft_record[8:12]), 16)
            print "Entries in Fixup Array:",                int(self.toBigEndian(mft_record[12:16]), 16)
            print "LogFile Sequence Number:",               int(self.toBigEndian(mft_record[16:32]), 16)
            print "Sequence number:",                       int(self.toBigEndian(mft_record[32:36]), 16)
            print "Hard link count:",                       int(self.toBigEndian(mft_record[36:40]), 16)
            first_attr_offset = int(self.toBigEndian(mft_record[40:44]), 16) * 2
            print "Offset to first attribute:",             first_attr_offset/2, "bytes"
            print "Offset to first attribute in hex:",      self.toBigEndian(mft_record[40:44])
            # This tells me that the file is deleted or in use
            print "Flags:",                                 int(self.toBigEndian(mft_record[44:48]), 16)
            print "Used size of MFT entry:",                int(self.toBigEndian(mft_record[48:56]), 16)
            print "Allocated size of MFT entry:",           int(self.toBigEndian(mft_record[56:64]), 16)
            print "File reference to the base FILE record:",int(self.toBigEndian(mft_record[64:80]), 16)
            print "Next attribute ID:",                     self.toBigEndian(mft_record[80:84])
            print "Number of this MFT record:",             int(self.toBigEndian(mft_record[88:96]), 16)
            print

            total_offset = first_attr_offset
            # Must go to the first attribute offset

            read_attributes = True

            while read_attributes:
                type_id = ATTRIBUTE_TYPES.get(mft_record[total_offset : total_offset + 8],"Unknown attribute")
                attr_length = int(self.toBigEndian(mft_record[total_offset + 8: total_offset + 16]), 16)
                form_code = self.toBigEndian(mft_record[total_offset + 16 : total_offset + 18])
                name_length = self.toBigEndian(mft_record[total_offset + 18 : total_offset + 20])
                offset_to_name = self.toBigEndian(mft_record[total_offset + 20 : total_offset + 24])
                flags = self.toBigEndian(mft_record[total_offset + 24 : total_offset + 28])
                attr_id = self.toBigEndian(mft_record[total_offset + 28 : total_offset + 30])

                print "Attribute Type is:", type_id
                print "Attribute Lengh is:", attr_length
                print "Attribute is:", "Resident" if form_code == "00" else "Non-Resident"
                print "File Name Length:", name_length
                print "Offset to Name:", offset_to_name
                print "Flags:", flags

                # Depending on which type, depends on how much of the record to read into
                file_record_hdr = ""

                if form_code == "00":
                    # resident
                    file_record_hdr = mft_record[total_offset: total_offset + 44 ]

                    # These are for resident attributes ONLY
                    content_size = int(self.toBigEndian(file_record_hdr[32:40]), 16)
                    offset_to_content = int(self.toBigEndian(file_record_hdr[40:44]), 16) * 2

                    # print non-resident attributes
                    print "\n------- RESIDENT ATTRIBUTES -------\n"
                    print "Attribute ID:",attr_id
                    print "Content Size:",content_size
                    print "Offset to Content:",offset_to_content
                else:
                    # non resident
                    file_record_hdr = mft_record[total_offset: total_offset + 128 ]

                    # These are for non-resident
                    starting_VCN          = self.toBigEndian(file_record_hdr[32:48])
                    ending_VCN            = self.toBigEndian(file_record_hdr[48:64])
                    offset_to_runlist     = self.toBigEndian(file_record_hdr[64:68])
                    compression_unit_size = self.toBigEndian(file_record_hdr[68:72])
                    unused                = self.toBigEndian(file_record_hdr[72:76])
                    allocated_size        = self.toBigEndian(file_record_hdr[76:92])
                    actual_size           = self.toBigEndian(file_record_hdr[92:108])
                    initialised_size      = self.toBigEndian(file_record_hdr[108:124])

                    # print non-resident attributes
                    print "\n------- NON-RESIDENT ATTRIBUTES -------\n"
                    print "Attribute ID:",attr_id
                    print "starting_VCN: ", starting_VCN
                    print "ending_VCN: ", ending_VCN
                    print "offset_to_runlist: ", offset_to_runlist
                    print "compression_unit_size: ", compression_unit_size
                    print "unused: ", unused
                    print "allocated_size: ", allocated_size
                    print "actual_size: ", actual_size
                    print "initialised_size: ", initialised_size


                print "OKAY!" if content_size + offset_to_content == attr_length else "PROBLEM!"

                file_record = mft_record[total_offset: total_offset + attr_length * 2]

                print "\n=================================\n"
                print file_record
                print "\n=================================\n"

                if type_id == "$STANDARD_INFORMATION":

                    print "\nprocessing $STANDARD_INFORMATION attribute\n"

                    file_Ctime = file_record[offset_to_content + 0: offset_to_content + 16]
                    file_Atime = file_record[offset_to_content + 16: offset_to_content + 32]
                    file_Mtime = file_record[offset_to_content + 32: offset_to_content + 48]
                    file_Rtime = file_record[offset_to_content + 48: offset_to_content + 64]

                    print mftutils.WindowsTime(int(file_Ctime[0:8],16), int(file_Ctime[8:16],16),False).dtstr
                    print "windows times:", file_Ctime

                    dos_permis = file_record[offset_to_content + 64: offset_to_content + 72]
                    max_no_versions = file_record[offset_to_content + 72: offset_to_content + 80]
                    version_no = file_record[offset_to_content + 80: offset_to_content + 88]
                    class_id = file_record[offset_to_content + 88: offset_to_content + 96]
                    owner_id = file_record[offset_to_content + 96: offset_to_content + 104]
                    securtiy_id = file_record[offset_to_content + 104: offset_to_content + 112]
                    quota_charged = file_record[offset_to_content + 112: offset_to_content + 128]
                    usn =  file_record[offset_to_content + 128: offset_to_content + 144]

                    print "C time:", file_Ctime
                    print "A time:", file_Atime
                    print "M time:", file_Mtime
                    print "R time:", file_Rtime
                    print "dos_permissions:", dos_permis
                    print "max_no_versions:", max_no_versions
                    print "version_no:", version_no
                    print "class_id:", class_id
                    print "owner_id:", owner_id
                    print "securtiy_id:", securtiy_id
                    print "quota_charged:", quota_charged
                    print "usn:", usn

                    # read_attributes.append("$STD_INFO")

                elif type_id == "$FILE_NAME":

                    print "\nprocessing $FILE_NAME attribute\n"
                    parent_dir_ref = file_record[offset_to_content: offset_to_content + 16]
                    file_create_time = file_record[offset_to_content + 16: offset_to_content + 32]
                    file_modification_time = file_record[offset_to_content + 32: offset_to_content + 48]
                    mft_modification_time = file_record[offset_to_content + 48: offset_to_content + 64]
                    file_access_time = file_record[offset_to_content + 64: offset_to_content + 80]
                    allocated_file_size = file_record[offset_to_content + 80: offset_to_content + 96]
                    real_file_size = file_record[offset_to_content + 96: offset_to_content + 112]
                    flags = file_record[offset_to_content + 112 :offset_to_content + 128]
                    # reparse_value = file_record[offset_to_content + 120: offset_to_content + 136]
                    # securtiy_id = file_record[offset_to_content + 128: offset_to_content + 136]
                    file_name_lenght_unicode = file_record[offset_to_content + 128: offset_to_content + 130]
                    file_name_namespace = file_record[offset_to_content + 130: offset_to_content + 132]
                    file_name_unicode = file_record[offset_to_content + 132: offset_to_content + 166].decode("hex")

                    print "parent_dir_ref", parent_dir_ref
                    print "file_create_time", file_create_time
                    print "file_modification_time", file_modification_time
                    print "mft_modification_time", mft_modification_time
                    print "file_access_time", file_access_time
                    print "allocated_file_size", allocated_file_size
                    print "real_file_size", real_file_size
                    print "flags", flags
                    # print "reparse_value", reparse_value
                    # print "securtiy_id", securtiy_id
                    print "file_name_lenght_unicode", file_name_lenght_unicode
                    print "file_name_namespace", file_name_namespace
                    print "file_name_unicode", file_name_unicode

                    read_attributes = False

                    # read_attributes.append("$FILE_NAME")

                elif type_id == "$DATA":
                    print "DATA Attributes go here..."
                    # read_attributes.append("$DATA")
                    read_attributes = False
                elif type_id == "$INDEX_ROOT":
                    # This is a directory entry
                    read_attributes = False
                    # # Parse Index root
                    # Attribute_Type = file_record[offset_to_content : offset_to_content + 8]
                    # Collation_Rule = file_record[offset_to_content + 8: offset_to_content + 16]
                    # Size_of_Index_Allocation_Entry  = file_record[offset_to_content + 16: offset_to_content + 24]
                    # Clusters_per_Index_Record = file_record[offset_to_content + 24: offset_to_content +  26]
                    # Padding  = file_record[offset_to_content + 26: offset_to_content + 32]

                    # print "Attribute_Type", ATTRIBUTE_TYPES.get(Attribute_Type,"Unknown")
                    # print "Collation_Rule", self.toBigEndian(Collation_Rule)
                    # print "Size_of_Index_Allocation_Entry", int(self.toBigEndian(Size_of_Index_Allocation_Entry),16)
                    # print "Clusters_per_Index_Record", int(self.toBigEndian(Clusters_per_Index_Record),16)
                    # print "Padding", self.toBigEndian(Padding)

                    # # Parse index header
                    # Offset_to_first_Index_Entry = int(self.toBigEndian(file_record[offset_to_content +  32: offset_to_content + 40]),16)
                    # Total_size_of_the_Index_Entries = int(self.toBigEndian(file_record[offset_to_content + 40 : offset_to_content + 48]),16)
                    # Allocated_size_of_the_Index_Entries = int(self.toBigEndian(file_record[offset_to_content + 48: offset_to_content + 56]),16)
                    # Flags = self.toBigEndian(file_record[offset_to_content + 56: offset_to_content + 58])
                    # Padding = int(self.toBigEndian(file_record[offset_to_content + 58: offset_to_content + 64]),16)


                    # print "Offset_to_first_Index_Entry", Offset_to_first_Index_Entry
                    # print "Total_size_of_the_Index_Entries", Total_size_of_the_Index_Entries
                    # print "Allocated_size_of_the_Index_Entries", Allocated_size_of_the_Index_Entries
                    # print "Flags", Flags
                    # print "Padding", Padding

                    # if flags == "01":
                    #     # Index Allocation used


                elif type_id == "$INDEX_ALLOCATION":
                    pass
                else:
                    read_attributes= False




                total_offset += attr_length * 2
                print
                print "total offset:", total_offset / 2
                print

            # Move address to next MFT entry
            address += 1024

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
    # if len(argv) == 2:
    #     file_path = argv[1]
    # else:
    #     # Display how to use if you don't give a file path
    #     print "Usage: python diskAnalyser.py <path_to_file>"
    #     sys.exit()
    print argv
    if len(argv) == 2:
        # default usage
        pass
    elif argv[2] == "-d":
        pass
        # out put list of deleted files
    elif argv[2] == "-r" and isinstance(argv[3], (int, long)):
        pass


    # HARD CODE THE FILE PATH FOR NOW
    file_path = "win7-vmdk-raw.001"

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
    vol_sec_address = int(p_info[1].get("Sector Start Address"),16)

    print "----- VOLUME INFO -----"
    NTFS_vol_info = disk_analyser.get_NTFS_vol_info(vol_sec_address)

    # With NTFS Volume info.
    # Calcluate physical sector address to find the MFT location.
    # mft_physical_address =  mft_logical_addr + (partitition sizes + partition start address')

    mft_cluster_location = NTFS_vol_info.get("MFT_cluster_location")
    sectors_per_cluster = NTFS_vol_info.get("sectors_per_cluster")

    mft_logical_addr = mft_cluster_location * sectors_per_cluster
    mft_physical_addr = (mft_logical_addr + (int(p_info[0].get("Sector Start Address"),16) + int(p_info[0].get("Partition Size"),16))) * SECTOR_SIZE

    print mft_logical_addr

    print "MFT Physical Sector Address: ", mft_physical_addr
    disk_analyser.get_MFT_info(mft_physical_addr)


if __name__ == '__main__':
    main(sys.argv)
