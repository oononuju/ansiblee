#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Varun Chopra (@chopraaa) <v@chopraaa.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = r'''
module: win_format
version_added: '2.8'
short_description: Formats an existing volume or a new volume on an existing partition on Windows
description:
  - The M(win_format) module formats an existing volume or a new volume on an existing partition on Windows
options:
  drive_letter:
    description:
      - Used to specify the drive letter of the volume to be formatted.
    type: str
  path:
    description:
      - Used to specify the path to the volume to be formatted.
    type: str
  label:
    description:
      - Used to specify the label of the volume to be formatted.
  new_label:
    description:
      - Used to specify the new file system label of the formatted volume.
  file_system:
    description:
      - Used to specify the file system to be used when formatting the target volume.
    type: str
    choices: [ ntfs, refs, exfat, fat32, fat ]
  allocation_unit_size:
    description:
      - Specifies the cluster size to use when formatting the volume.
      - If no cluster size is specified when you format a partition, defaults are selected based on
        the size of the partition.
    type: int
  large_frs:
    description:
      - Specifies that large File Record System (FRS) should be used.
  compress:
    description:
      - Enable compression on the resulting NTFS volume.
      - NTFS compression is not supported where I(allocation_unit_size) is more than 4096.
    type: bool
  integrity_streams:
    description:
      - Enable integrity streams on the resulting ReFS volume.
  full:
    description:
      - A full format writes to every sector of the disk, takes much longer to perform than the 
        default (quick) format, and is not recommended on storage that is thinly provisioned.
      - Specify C(true) for full format.
    type: bool
  force:
    description:
      - Specify if formatting should be forced for volumes that are not created from new partitions.
      - Volumes that have been formatted previously or contain data must be force-formatted.
notes:
  - One of three parameters (drive_letter, path and label) are mandatory to identify the target 
    volume but more than one cannot be specified at the same time.
  - This module cannot be used for changing the drive letter of a pre-existing partition or volume.
    Refer to the M(win_access_path) module for setting and removing drive letters.
  - For more information, see U(https://docs.microsoft.com/en-us/previous-versions/windows/desktop/stormgmt/format-msft-volume)
author:
  - Varun Chopra (@chopraaa) <v@chopraaa.com>
'''

EXAMPLES = r'''
- name: Create a partition with drive letter D and size 5 GiB
  win_partition:
    drive_letter: D
    partition_size: 5 GiB
    disk_number: 1

- name: Full format the newly created partition as NTFS and label it
  win_format:
    drive_letter: D
    file_system: NTFS
    new_label: Formatted
    full: True
'''

RETURN = r'''
#
'''
