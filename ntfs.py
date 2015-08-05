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
import csv

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
        self.mft_location = 0

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

    def get_NTFS_vol_info(self, volume_num, address):
        """ Get Information NTFS Volume"""

        # Get NTFS BPB and Extended BPB code.
        vol_info = self.read_disk_info(address, False, True)

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

        ntfs_vol_info = {"volume_num": volume_num,
                         "bytes_per_sector" : bytes_per_sector,
                         "sectors_per_cluster" : sectors_per_cluster,
                         "MFT_cluster_location" : MFT_cluster_location}

        return ntfs_vol_info



    def get_MFT_info(self, address):

        hasFiles = True
        record_num = 0
        rows = []
        isGood = "Good"
        record_type = "File"
        filename = ""

        count = 0
        while hasFiles:

            mft_record = self.get_disk_info(address, 1024)
            print "MFT File Record: ", record_num
            record_num += 1
            print "magic number:",                          mft_record[0:8].decode("hex")
            if mft_record[0:8].decode("hex") != "FILE":
                # terminate
                hasFiles = False
                isGood = "Bad"


            update_sequence_offset  = int(self.toBigEndian(mft_record[8:12]), 16)
            fixup_entries_array = int(self.toBigEndian(mft_record[12:16]), 16)
            logfile_sequence_num = int(self.toBigEndian(mft_record[16:32]), 16)
            sequence_number = int(self.toBigEndian(mft_record[32:36]), 16)
            hardlink_count =   int(self.toBigEndian(mft_record[36:40]), 16)
            offset_to_first_attribute = int(self.toBigEndian(mft_record[40:44]), 16)
            flags = int(self.toBigEndian(mft_record[44:48]), 16)
            used_mft_size = int(self.toBigEndian(mft_record[48:56]), 16)
            allocated_mft_size = int(self.toBigEndian(mft_record[56:64]), 16)
            reference_to_base_file = int(self.toBigEndian(mft_record[64:80]), 16)
            next_atttribute_id = self.toBigEndian(mft_record[80:84])
            record_num  = int(self.toBigEndian(mft_record[88:96]), 16)

            print "update sequence offset:",
            print "Entries in Fixup Array:",
            print "LogFile Sequence Number:",
            print "Sequence number:",
            print "Hard link count:",
            first_attr_offset = int(self.toBigEndian(mft_record[40:44]), 16) * 2
            print "Offset to first attribute:",             first_attr_offset/2, "bytes"
            print "Offset to first attribute in hex:",      self.toBigEndian(mft_record[40:44])
            # This tells me that the file is deleted or in use
            print "Flags:",
            print "Used size of MFT entry:",
            print "Allocated size of MFT entry:",
            print "File reference to the base FILE record:",
            print "Next attribute ID:",
            print "Number of this MFT record:",
            print

            total_offset = first_attr_offset
            # Must go to the first attribute offset

            read_attributes = True
            isFile = True

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

                    file_name_lenght_unicode = int(self.toBigEndian(file_record[offset_to_content + 128: offset_to_content + 130]),16)
                    file_name_namespace = file_record[offset_to_content + 130: offset_to_content + 132]
                    filename = file_record[offset_to_content + 132: offset_to_content + 132 +(file_name_lenght_unicode*2) +32].decode("hex").encode("utf-8")

                    print "parent_dir_ref", parent_dir_ref
                    print "file_create_time", file_create_time
                    print "file_modification_time", file_modification_time
                    print "mft_modification_time", mft_modification_time
                    print "file_access_time", file_access_time
                    print "allocated_file_size", allocated_file_size
                    print "real_file_size", real_file_size
                    print "flags", flags
                    print "file_name_lenght_unicode", file_name_lenght_unicode
                    print "file_name_namespace", file_name_namespace
                    print "file_name_unicode", filename

                    read_attributes = False

                elif type_id == "$DATA":
                    print "DATA Attributes go here..."
                    # read_attributes.append("$DATA")
                    read_attributes = False
                elif type_id == "$INDEX_ROOT":
                    # This is a directory entry
                    isFile = False
                    read_attributes = False
                    # Parse Index root
                    Attribute_Type = file_record[offset_to_content : offset_to_content + 8]
                    Collation_Rule = file_record[offset_to_content + 8: offset_to_content + 16]
                    Size_of_Index_Allocation_Entry  = file_record[offset_to_content + 16: offset_to_content + 24]
                    Clusters_per_Index_Record = file_record[offset_to_content + 24: offset_to_content +  26]
                    Padding  = file_record[offset_to_content + 26: offset_to_content + 32]

                    print "Attribute_Type", ATTRIBUTE_TYPES.get(Attribute_Type,"Unknown")
                    print "Collation_Rule", self.toBigEndian(Collation_Rule)
                    print "Size_of_Index_Allocation_Entry", int(self.toBigEndian(Size_of_Index_Allocation_Entry),16)
                    print "Clusters_per_Index_Record", int(self.toBigEndian(Clusters_per_Index_Record),16)
                    print "Padding", self.toBigEndian(Padding)

                    # Parse index header
                    Offset_to_first_Index_Entry = int(self.toBigEndian(file_record[offset_to_content +  32: offset_to_content + 40]),16)
                    Total_size_of_the_Index_Entries = int(self.toBigEndian(file_record[offset_to_content + 40 : offset_to_content + 48]),16)
                    Allocated_size_of_the_Index_Entries = int(self.toBigEndian(file_record[offset_to_content + 48: offset_to_content + 56]),16)
                    Flags = self.toBigEndian(file_record[offset_to_content + 56: offset_to_content + 58])
                    Padding = int(self.toBigEndian(file_record[offset_to_content + 58: offset_to_content + 64]),16)


                    print "Offset_to_first_Index_Entry", Offset_to_first_Index_Entry
                    print "Total_size_of_the_Index_Entries", Total_size_of_the_Index_Entries
                    print "Allocated_size_of_the_Index_Entries", Allocated_size_of_the_Index_Entries
                    print "Flags", Flags
                    print "Padding", Padding

                elif type_id == "$INDEX_ALLOCATION":
                    pass
                else:
                    read_attributes= False

                total_offset += attr_length * 2
                print
                print "total offset:", total_offset / 2
                print

            if  not isFile:
                record_type = "Folder"

            row = [record_num,
                   isGood,
                   record_type,
                   filename,
                   sequence_number,
                   hardlink_count,
                   flags,
                   used_mft_size,
                   allocated_mft_size,
                   logfile_sequence_num,
                   reference_to_base_file]

            count += 1

            # if count >= 30:
            #     return rows


            rows.append(map(str,row))
            # Move address to next MFT entry
            address += 1024

        return rows

    def display_disk_info(self):
        p_info = self.get_partition_info()

        part_info = []
        vol_info = []

        print "----- PARTITION INFO -----"
        print "Number of Visible Partitions:", len(p_info)
        read_parts = False

        for i in xrange(len(p_info)):
            print "Partition #", p_info[i].get("Partition #")
            print "Start Sector Address:", p_info[i].get("Sector Start Address"), p_info[i].get("Sector Start Address_str")
            print "Partition Size:", int(p_info[i].get("Partition Size"),16),"Sectors",
            print "OR Approximately", size(int(p_info[i].get("Partition Size"),16) * SECTOR_SIZE)
            print "File System Type:", p_info[i].get("Type"), p_info[i].get("Type_str")
            print

        for i in xrange(len(p_info)):
            # Get NTFS volume address in decimal
            vol_sec_address = int(p_info[i].get("Sector Start Address"),16)

            print "----- VOLUME INFO FOR PARTITION %i -----" % i
            NTFS_vol_info = self.get_NTFS_vol_info(i, vol_sec_address)
            vol_info.append(NTFS_vol_info)
            print

        return p_info, vol_info

    def output_to_CSV(self, someiterable):

        fieldnames = ["Record Number",
                      "Good or Bad",
                      "Record_Type",
                      "Filename",
                      "File Sequence No",
                      "Hardlink Count",
                      "Flags",
                      "Used MFT Size",
                      "Allocated MFT Size",
                      "Logfile Sequence No",
                      "Parent File Reference",
                      "update_sequence_offset"]
        printHeader = False

        print someiterable
        import codecs
        f = codecs.open("some1.csv",'w','utf-8')
        for row in someiterable:
            for i in row:
                f.write(i + ",")

            f.write("\n")
        f.close()



def main(argv):
    print argv

    parseMFT = False
    volume_no = 0
    if len(argv) == 1:
        # Display how to use if you don't give a file path
        print "Usage: python diskAnalyser.py <path_to_file> -mft <- Optional"
        sys.exit()
    elif len(argv) == 2:
        file_path = argv[1]
    elif len(argv) >= 2 and argv[2] == "-mft" and isinstance(int(argv[3]), int):
        # Parse MFT of a given volume
        file_path = argv[1]
        parseMFT = True
        volume_no = int(argv[3])


    # Create diskAnalyser object, with a file path
    disk_analyser = DiskAnalyser(file_path)

    # Default usage - Get partition information from MBR (Master Boot Record)
    partition_info, volume_info = disk_analyser.display_disk_info()

    if parseMFT:
        mft_cluster_location = volume_info[volume_no].get("MFT_cluster_location")
        sectors_per_cluster = volume_info[volume_no].get("sectors_per_cluster")

        mft_logical_addr = mft_cluster_location * sectors_per_cluster
        mft_physical_addr = 0

        i = 0
        while i < volume_no:
            mft_physical_addr += int(partition_info[i].get("Sector Start Address"),16) + int(partition_info[i].get("Partition Size"),16)
            i += 1

        mft_physical_addr += mft_logical_addr
        mft_physical_addr = mft_physical_addr * SECTOR_SIZE

        print "MFT location", mft_physical_addr
        rows = disk_analyser.get_MFT_info(mft_physical_addr)
        disk_analyser.output_to_CSV(rows)

if __name__ == '__main__':
    main(sys.argv)
