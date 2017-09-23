#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Kairo Araujo <kairo@kairo.eti.br>
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
author: Kairo Araujo (@kairoaraujo)
module: aix_filesystem
short_description: Configure basics LVM and NFS file systems for AIX.
description:
  - This module creates, removes, mount and unmount LVM and NFS file system for
    AIX using /etc/filesystems. For LVM file systems is also possible to resize
    the file system.
version_added: "2.5"
options:
  account_subsystem:
    description:
      - Specifies whether the file system is to be processed by the accounting
        subsystem.
    choices: ["yes", "no"]
    default: "no"
    required: false
  attributes:
    description:
      - Specifies attributes for files system.
    default: agblksize='4096',isnapshot='no'
    required: false
  auto_mount:
    description:
      - File system is automatically mounted at system restart.
    choices: ["yes", "no"]
    default: "yes"
    required: false
  device:
    description:
      - Logical volume (LV) name or device to create the filesystem (NFS). It
        is used to create a file system on an already existing logical volume.
        If not mentioned a new logical name will be created.
    default: None
    required: false
  fs_type:
    description:
      - Specifies the virtual file system type.
    default: jfs2
    required: no
  permissions:
    description:
      - Set file system permissions. rw (read-write), ro(read-only)
    choices: [rw, ro]
    default: rw
    required: false
  mount_group:
    description:
      - Specifies the mount group.
    required: false
  filesystem:
    description:
      - Specifies the mount point, which is the directory where the file system
        will be mounted.
    required: true
  nfs_server:
    description:
      - Specifies a Network File System (NFS) server.
    default: None
    required: false
  rm_mount_point:
    description:
      - Remove the mount point directory when used with state C(absent).
    default: false
    required: false
  size:
    description:
      - Specifies the file system size.
        For already C(present) it will be resized.
        512-byte blocks, Megabytes or Gigabytes. If the value has M specified
        it will be in Megabytes. If the value has G specified it will be in
        Gigabytes.
        If no M or G the value will be  512-byte blocks.
        If "+" is specified in begin of value, the value will be added. If "-"
        is specified in begin of value, the value will be removed. If "+" or
        "-" is not specified, the total value will be the specified.
        Size will respect the LVM AIX standards.
    required: false
  state:
    description:
      - Controls the file system state.
        C(present) check if exists or creates.
        C(absent) removes and existing file system if already C(unmounted).
        C(mounted) checks if the state is mounted or mount a file system.
        C(unmounted) check if state is unmounted or unmount a files system.
    choices: [present, absent, mounted, unmounted]
    default: present
    required: true
  vg:
    description:
      - Specifies an existing volume group (VG).
    required: true
notes:
  - For more C(attributes), please check "crfs" AIX manuals.
'''

EXAMPLES = '''
- name: Create filesystem in a previously defined logical volume.
  aix_filesystem:
    device: testlv
    filesystem: /testfs
    state: present
- name: Creating NFS filesystem from nfshost.
  aix_filesystem:
    device: /home/ftp
    nfs_server: nfshost
    filesystem: /home/ftp
    state: present
- name: Creating a new file system without a previously logical volume.
  aix_filesystem:
    filesystem: /newfs
    size: 1G
    state: present
    vg: datavg
- name: Unmounting /testfs.
  aix_filesystem:
    filesystem: /testfs
    state: unmounted
- name: Resizing /mksysb to +512M.
  aix_filesystem:
    filesystem: /mksysb
    size: +512M
    state: present
- name: Resizing /mksysb to 11G.
  aix_filesystem:
    filesystem: /mksysb
    size: 11G
    state: present
- name: Resizing /mksysb to -2G.
  aix_filesystem:
    filesystem: /mksysb
    size: -2G
    state: present
- name: Remove NFS filesystem /home/ftp.
  aix_filesystem:
    filesystem: /home/ftp
    rm_mount_point: yes
    state: absent
- name: Remove /newfs.
  aix_filesystem:
    filesystem: /newfs
    rm_mount_point: yes
    state: absent
'''

RETURN = '''
changed:
  description: Return changed for aix_filesystems actions as true or false.
  returned: always
  type: boolean
  version_added: 2.5
msg:
  description: Return message regarding the action.
  returned: always
  type: string
  version_added: 2.5
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ismount import ismount
import re


def _fs_exists(module, filesystem):
    """
    Check if file system already exists on /etc/filesystems.

    :param module: Ansible module.
    :param filesystem: filesystem name.
    :return: True or False.
    """
    lsfs_cmd = module.get_bin_path('lsfs', True)
    rc, lsfs_out, err = module.run_command(
        "%s -l %s" % (lsfs_cmd, filesystem))
    if rc == 1:
        if re.findall("No record matching", err):
            return False

        else:
            module.fail_json(msg="Failed to run lsfs.", rc=rc, err=err)

    else:

        return True


def _check_nfs_device(module, nfs_host, device):
    """
    Validate if NFS server is exporting the device (remote export).

    :param module: Ansible module.
    :param nfs_host: nfs_host parameter, NFS server.
    :param device: device parameter, remote export.
    :return: True or False.
    """
    showmount_cmd = module.get_bin_path('showmount', True)
    rc, showmount_out, err = module.run_command(
        "%s -a %s" % (showmount_cmd, nfs_host))
    if rc != 0:
        module.fail_json(msg="Failed to run showmount.", rc=rc, err=err)
    else:
        showmount_data = showmount_out.splitlines()
        for line in showmount_data:
            if line.split(':')[1] == device:
                return True

        return False


def _validate_vg(module, vg):
    """
    Check the current state of volume group.

    :param module: Ansible module argument spec.
    :param vg: Volume Group name.
    :return: True (VG in varyon state) or False (VG in varyoff state) or
             None (VG does not exist), message.
    """
    lsvg_cmd = module.get_bin_path('lsvg', True)
    rc, current_active_vgs, err = module.run_command("%s -o" % lsvg_cmd)
    if rc != 0:
        module.fail_json(msg="Failed executing %s command." % lsvg_cmd)

    rc, current_all_vgs, err = module.run_command("%s" % lsvg_cmd)
    if rc != 0:
        module.fail_json(msg="Failed executing %s command." % lsvg_cmd)

    if vg in current_all_vgs and vg not in current_active_vgs:
        msg = "Volume group %s is in varyoff state." % vg
        return False, msg
    elif vg in current_active_vgs:
        msg = "Volume group %s is in varyon state." % vg
        return True, msg
    else:
        msg = "Volume group %s does not exist." % vg
        return None, msg


def resize_fs(module, filesystem, size):
    """ Resize LVM file system. """

    chfs_cmd = module.get_bin_path('chfs', True)
    if not module.check_mode:
        rc, chfs_out, err = module.run_command(
            '%s -a size="%s" %s' % (chfs_cmd, size, filesystem))

        if rc == 28:
            changed = False

            return changed, chfs_out

        elif rc != 0:
            if re.findall('Maximum allocation for logical', err):
                changed = False

                return changed, err

            else:
                module.fail_json("Failed to run chfs.", rc=rc, err=err)

        else:
            if re.findall('The filesystem size is already', chfs_out):
                changed = False
            else:
                changed = True

            return changed, chfs_out
    else:
        changed = True
        msg = ''

        return changed, msg


def create_fs(
        module, fs_type, filesystem, vg, device, size, mount_group, auto_mount,
        account_subsystem, permissions, nfs_server, attributes):
    """ Create LVM file system or NFS remote mount point. """

    attributes = ' -a '.join(attributes)

    # Parameters definition.
    account_subsys_opt = {
        True: '-t yes',
        False: '-t no'
    }


    if nfs_server is not None:
        auto_mount_opt = {
            True: '-A',
            False: '-a'
        }

    else:
        auto_mount_opt = {
            True: '-A yes',
            False: '-A no'
        }

    if size is None:
        size = ''
    else:
        size = "-a size=%s" % size

    if device is None:
        device = ''
    else:
        device = "-d %s" % device

    if vg is None:
        vg = ''
    else:
        vg_state, msg = _validate_vg(module, vg)
        if vg_state:
            vg = "-g %s" % vg
        else:
            changed = False

            return changed, msg

    if mount_group is None:
        mount_group = ''

    else:
        mount_group = "-u %s" % mount_group

    auto_mount = auto_mount_opt[auto_mount]
    account_subsystem = account_subsys_opt[account_subsystem]

    if nfs_server is not None:
        # Creates a NFS file system.
        mknfsmnt_cmd = module.get_bin_path('mknfsmnt', True)
        if not module.check_mode:
            rc, mknfsmnt_out, err = module.run_command(
                '%s -f "%s" %s -h "%s" -t "%s" "%s" -w "bg"' % (
                    mknfsmnt_cmd, filesystem, device, nfs_server, permissions,
                    auto_mount))
            if rc != 0:
                module.fail_json(msg="Failed to run mknfsmnt.", rc=rc, err=err)
            else:
                changed = True
                msg = "NFS file system %s created." % filesystem

                return changed, msg
        else:
            changed = True
            msg = ''

            return changed, msg

    else:
        # Creates a LVM file system.
        crfs_cmd = module.get_bin_path('crfs', True)
        if not module.check_mode:
            rc, crfs_out, err = module.run_command(
                "%s -v %s -m %s %s %s %s %s %s -p %s %s -a %s" % (
                    crfs_cmd, fs_type, filesystem, vg, device, mount_group,
                    auto_mount, account_subsystem, permissions, size,
                    attributes))
            if rc != 0:
                module.fail_json(msg="Failed to run crfs.", rc=rc, err=err)

            else:
                changed = True
                return changed, crfs_out
        else:
            changed = True
            msg = ''

            return changed, msg


def remove_fs(module, filesystem, rm_mount_point):
    """ Remove an LVM file system or NFS entry. """

    # Command parameters.
    rm_mount_point_opt = {
        True: '-r',
        False: ''
    }

    rm_mount_point = rm_mount_point_opt[rm_mount_point]

    rmfs_cmd = module.get_bin_path('rmfs', True)
    if not module.check_mode:
        rc, rmfs_out, err = module.run_command(
            "%s -r %s %s" % (rmfs_cmd, rm_mount_point, filesystem))
        if rc != 0:
            module.fail_json(msg="Failed to run rmfs.", rc=rc, err=err)
        else:
            changed = True
            msg = rmfs_out
            if not rmfs_out:
                msg = "File system %s removed." % filesystem

            return changed, msg
    else:
        changed = True
        msg = ''

        return changed, msg


def mount_fs(module, filesystem):
    """ Mount a file system. """
    mount_cmd = module.get_bin_path('mount', True)

    if not module.check_mode:
        rc, mount_out, err = module.run_command(
            "%s %s" % (mount_cmd, filesystem))
        if rc != 0:
            module.fail_json("Failed to run mount.", rc=rc, err=err)
        else:
            changed = True
            msg = "File system %s mounted." % filesystem

            return changed, msg
    else:
        changed = True
        msg = ''

        return changed, msg


def unmount_fs(module, filesystem):
    """ Unmount a file system."""
    unmount_cmd = module.get_bin_path('unmount', True)

    if not module.check_mode:
        rc, unmount_out, err = module.run_command(
            "%s %s" % (unmount_cmd, filesystem))
        if rc != 0:
            module.fail_json("Failed to run unmount.", rc=rc, err=err)
        else:
            changed = True
            msg = "File system %s unmounted." % filesystem

            return changed, msg
    else:
        changed = True
        msg = ''

        return changed, msg


def main():
    module = AnsibleModule(
        argument_spec=dict(
            account_subsystem=dict(type='bool', default=False),
            attributes=dict(
                type='list', default=['agblksize="4096"', 'isnapshot="no"']),
            auto_mount=dict(type='bool', default=True),
            device=dict(type='str', default=None),
            filesystem=dict(type='str', required=True),
            fs_type=dict(type='str', default='jfs2', required=False),
            permissions=dict(choices=['rw', 'ro'], default='rw'),
            mount_group=dict(type='str', default=None),
            nfs_server=dict(type='str', default=None),
            rm_mount_point=dict(type='bool', default=False),
            size=dict(type='str', default=None),
            state=dict(
                choices=['absent', 'present', 'mounted', 'unmounted'],
                default='present'),
            vg=dict(type='str')
        ),
        supports_check_mode=True
    )

    account_subsystem = module.params['account_subsystem']
    attributes = module.params['attributes']
    auto_mount = module.params['auto_mount']
    device = module.params['device']
    fs_type = module.params['fs_type']
    permissions = module.params['permissions']
    mount_group = module.params['mount_group']
    filesystem = module.params['filesystem']
    nfs_server = module.params['nfs_server']
    rm_mount_point = module.params['rm_mount_point']
    size = module.params['size']
    state = module.params['state']
    vg = module.params['vg']

    if state == 'present':
        changed = False
        msg = ''
        fs_mounted = ismount(filesystem)
        fs_exists = _fs_exists(module, filesystem)

        # Check if fs is mounted or exists.
        if fs_mounted or fs_exists:
            msg = "File system %s already exists." % filesystem
            changed = False

            # If parameter size was passed, resize fs.
            if size is not None:
                changed, msg = resize_fs(module, filesystem, size)

        # If fs doesn't exist, create it.
        else:
            # Check if fs will be a NFS device.
            if nfs_server is not None:
                if device is None:
                    changed = False
                    msg = ''
                    module.fail_json(
                        msg='Parameter "device" is required when "nfs_server" '
                            'is defined.')
                else:
                    # Create a fs from NFS export.
                    if _check_nfs_device(module, nfs_server, device):
                        changed, msg = create_fs(
                            module, fs_type, filesystem, vg, device, size,
                            mount_group, auto_mount, account_subsystem,
                            permissions, nfs_server, attributes)

            if device is None:
                if vg is None:
                    changed = False
                    msg = ''
                    module.fail_json(
                        msg='Parameter "vg" is required when a "device" is not'
                            ' defined.')
                else:
                    # Create a fs from
                    changed, msg = create_fs(
                        module, fs_type, filesystem, vg, device, size,
                        mount_group, auto_mount, account_subsystem,
                        permissions, nfs_server, attributes)

            if device is not None and nfs_server is None:
                # Create a fs from a previously lv device.
                changed, msg = create_fs(
                    module, fs_type, filesystem, vg, device, size, mount_group,
                    auto_mount, account_subsystem, permissions, nfs_server,
                    attributes)

    elif state == 'absent':
        if ismount(filesystem):
            changed = False
            msg = "File system mounted."
        else:
            fs_status = _fs_exists(module, filesystem)
            if not fs_status:
                changed = False
                msg = "File system does not exist."
            else:
                changed, msg = remove_fs(module, filesystem, rm_mount_point)

    elif state == 'mounted':
        if ismount(filesystem):
            changed = True
            msg = "File system already mounted."
        else:
            changed, msg = mount_fs(module, filesystem)

    elif state == 'unmounted':
        if not ismount(filesystem):
            changed = False
            msg = "File system already unmounted."
        else:
            changed, msg = unmount_fs(module, filesystem)

    else:
        changed = False
        msg = ''
        module.fail_json(msg="Unexpected state %s." % state)

    module.exit_json(changed=changed, msg=msg)


if __name__ == '__main__':
    main()
