# -*- coding: utf-8 -*-
# Copyright (c) 2020 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import pytest


from ansible.module_utils.facts.virtual import linux


def mock_os_path_is_file_docker(filename):
    return filename in ("/.dockerenv", "/.dockerinit")


def mock_os_path_proc_1_cgroup(filename):
    return filename in ("/proc/1/cgroup",)


def mock_os_path_proc_1_environ(filename):
    return filename in ("/proc/1/environ",)


def mock_openvz_host_path(filename):
    return filename in ("/proc/vz", "/proc/bc")


def mock_openvz_guest_path(filename):
    return filename in ("/proc/vz",)


def mock_proc_xen_guest_path(filename):
    return filename in ("/proc/xen",)


def mock_proc_self_status(filename):
    return filename in ("/proc/self/status",)


def mock_proc_cpuinfo(filename):
    return filename in ("/proc/cpuinfo",)


def mock_proc_modules(filename, _dummy=None):
    return filename in ("/proc/modules",)


def mock_dev_kvm(filename):
    return filename in ("/dev/kvm",)


def mock_filepath_rhv(filename):
    return filename in (
        "/sys/devices/virtual/dmi/id/sys_vendor",
        "/sys/devices/virtual/dmi/id/product_family",
    )


def mock_filepath_rhev(filename):
    return filename in (
        "/sys/devices/virtual/dmi/id/sys_vendor",
        "/sys/devices/virtual/dmi/id/product_name",
    )


def mock_filepath_product_name(filename):
    return filename in ("/sys/devices/virtual/dmi/id/product_name",)


def mock_filepath_bios_vendor(filename):
    return filename in ("/sys/devices/virtual/dmi/id/bios_vendor",)


def mock_filepath_sys_vendor(filename):
    return filename in ("/sys/devices/virtual/dmi/id/sys_vendor",)


def mock_get_file_content_xen(filename):
    return "Xen" if filename == "/sys/devices/virtual/dmi/id/bios_vendor" else None


def mock_get_file_content_kvm(filename):
    return "KVM" if filename == "/sys/devices/virtual/dmi/id/product_name" else None


def mock_get_file_content_ovirt(filename):
    return "oVirt" if filename == "/sys/devices/virtual/dmi/id/sys_vendor" else None


def mock_get_file_content_rhv(filename):
    file_data = {
        "/sys/devices/virtual/dmi/id/sys_vendor": "Red Hat",
        "/sys/devices/virtual/dmi/id/product_family": "RHV",
    }
    return file_data.get(filename, None)


def mock_get_file_content_rhev(filename):
    file_data = {
        "/sys/devices/virtual/dmi/id/sys_vendor": "Red Hat",
        "/sys/devices/virtual/dmi/id/product_name": "RHEV Hypervisor",
    }
    return file_data.get(filename, None)


def mock_get_file_content_vmware(filename):
    return "VMware" if filename == "/sys/devices/virtual/dmi/id/product_name" else None


def mock_get_file_content_openstack(filename):
    if filename == "/sys/devices/virtual/dmi/id/product_name":
        return "OpenStack Compute"
    return None


def mock_get_file_content_xen_bios_vendor(filename):
    return "Xen" if filename == "/sys/devices/virtual/dmi/id/bios_vendor" else None


def mock_get_file_content_virtualbox(filename):
    if filename == "/sys/devices/virtual/dmi/id/bios_vendor":
        return "innotek GmbH"
    return None


def mock_get_file_content_nutanix(filename):
    return "Nutanix" if filename == "/sys/devices/virtual/dmi/id/sys_vendor" else None


def mock_get_file_content_kubevirt(filename):
    return "KubeVirt" if filename == "/sys/devices/virtual/dmi/id/sys_vendor" else None


def mock_get_file_content_microsoft(filename):
    if filename == "/sys/devices/virtual/dmi/id/sys_vendor":
        return "Microsoft Corporation"
    return None


def mock_get_file_content_parallel(filename):
    if filename == "/sys/devices/virtual/dmi/id/sys_vendor":
        return "Parallels Software International Inc."
    return None


def mock_get_file_content_openstack_sys(filename):
    if filename == "/sys/devices/virtual/dmi/id/sys_vendor":
        return "OpenStack Foundation"
    return None


def mock_get_file_lines_linuxvserver_guest(filename):
    return ["VxID: 42"] if filename == "/proc/self/status" else []


def mock_get_file_lines_linuxvserver_host(filename):
    return ["VxID: 0"] if filename == "/proc/self/status" else []


def mock_get_file_lines_proc_cpuinfo_qemu(filename):
    if filename == "/proc/cpuinfo":
        return ["model name : QEMU Virtual CPU version 0.14.0"]
    return []


def mock_get_file_lines_proc_cpuinfo_uml(filename):
    if filename == "/proc/cpuinfo":
        return ["vendor_id : User Mode Linux", "model name : UML"]
    return []


def mock_get_file_lines_proc_cpuinfo_ibm(filename):
    if filename == "/proc/cpuinfo":
        return ["machine : CHRP IBM pSeries (emulated by qemu)"]
    return []


def mock_get_file_lines_proc_cpuinfo_powervm(filename):
    return ["vendor_id : PowerVM Lx86"] if filename == "/proc/cpuinfo" else []


def mock_get_file_lines_proc_cpuinfo_ibms390(filename):
    return ["vendor_id : IBM/S390"] if filename == "/proc/cpuinfo" else []


def mock_get_file_lines_proc_modules_kvm(filename):
    return ["kvm 1729"] if filename == "/proc/modules" else []


def mock_get_file_lines_proc_modules_virtualbox(filename):
    return ["vboxdrv 1729"] if filename == "/proc/modules" else []


def mock_get_file_lines_proc_modules_virtio(filename):
    return ["virtio 1729"] if filename == "/proc/modules" else []


def test_get_virtual_facts_docker(mocker):
    mocker.patch("os.path.exists", side_effect=mock_os_path_is_file_docker)

    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()

    expected = {
        "virtualization_role": "guest",
        "virtualization_tech_host": set(),
        "virtualization_type": "docker",
        "virtualization_tech_guest": set(["docker", "container"]),
    }

    assert facts == expected


@pytest.mark.parametrize(
    ("proc_1_cgroup_data", "virtualization_type"),
    (
        pytest.param(
            [
                "/docker/afd862d2ed48ef5dc0ce8f1863e4475894e331098c9a512789233ca9ca06fc62.scope"
            ],
            "docker",
            id="docker",
        ),
        pytest.param(
            ["/lxc/"],
            "lxc",
            id="lxc",
        ),
        pytest.param(
            ["/system.slice/containerd.service"],
            "containerd",
            id="containerd",
        ),
    ),
)
def test_get_virtual_facts_docker_cgroup(mocker, proc_1_cgroup_data, virtualization_type):
    mocker.patch("os.path.exists", side_effect=mock_os_path_proc_1_cgroup)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_lines",
        return_value=proc_1_cgroup_data,
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)

    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "guest",
        "virtualization_tech_host": set(),
        "virtualization_type": virtualization_type,
        "virtualization_tech_guest": set([virtualization_type, "container"]),
    }

    assert facts == expected


@pytest.mark.parametrize(
    ("proc_1_environ_data", "virtualization_type"),
    (
        pytest.param(
            ["container=lxc"],
            "lxc",
            id="lxc",
        ),
        pytest.param(
            ["container=podman"],
            "podman",
            id="podman",
        ),
        pytest.param(
            ["container=."],
            "container",
            id="container",
        ),
    ),
)
def test_get_virtual_facts_container(mocker, proc_1_environ_data, virtualization_type):
    mocker.patch("os.path.exists", side_effect=mock_os_path_proc_1_environ)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_lines",
        return_value=proc_1_environ_data,
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)

    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "guest",
        "virtualization_tech_host": set(),
        "virtualization_type": virtualization_type,
        "virtualization_tech_guest": set([virtualization_type, "container"]),
    }

    assert facts == expected


def test_get_virtual_facts_openvz_host(mocker):
    mocker.patch("os.path.exists", side_effect=mock_openvz_host_path)
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)

    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "host",
        "virtualization_tech_guest": set(),
        "virtualization_type": "openvz",
        "virtualization_tech_host": set(["openvz"]),
    }
    assert facts == expected


def test_get_virtual_facts_openvz_guest(mocker):
    mocker.patch("os.path.exists", side_effect=mock_openvz_guest_path)
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)

    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "guest",
        "virtualization_tech_guest": set(["container", "openvz"]),
        "virtualization_type": "openvz",
        "virtualization_tech_host": set(),
    }
    assert facts == expected


def test_get_virtual_facts_procxen_host(mocker):
    mocker.patch("os.path.exists", side_effect=mock_proc_xen_guest_path)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_lines",
        return_value=["control_d"],
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)

    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "host",
        "virtualization_tech_guest": set(),
        "virtualization_type": "xen",
        "virtualization_tech_host": set(["xen"]),
    }
    assert facts == expected


def test_get_virtual_facts_procxen_guest(mocker):
    mocker.patch("os.path.exists", side_effect=mock_proc_xen_guest_path)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_lines", return_value=[]
    )
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_content",
        side_effect=mock_get_file_content_xen,
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()

    expected = {
        "virtualization_role": "guest",
        "virtualization_tech_guest": set(["xen"]),
        "virtualization_type": "xen",
        "virtualization_tech_host": set(),
    }
    assert facts == expected


def test_get_virtual_facts_kvm_guest(mocker):
    mocker.patch("os.path.exists", side_effect=mock_filepath_product_name)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_content",
        side_effect=mock_get_file_content_kvm,
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "guest",
        "virtualization_tech_guest": set(["kvm"]),
        "virtualization_type": "kvm",
        "virtualization_tech_host": set(),
    }
    assert facts == expected


def test_get_virtual_facts_ovirt_guest(mocker):
    mocker.patch("os.path.exists", side_effect=mock_filepath_sys_vendor)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_content",
        side_effect=mock_get_file_content_ovirt,
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "guest",
        "virtualization_tech_guest": set(["oVirt"]),
        "virtualization_type": "oVirt",
        "virtualization_tech_host": set(),
    }
    assert facts == expected


@pytest.mark.parametrize(
    ("mock_method", "mock_filepath_method", "expected_hypervisor"),
    [
        pytest.param(
            mock_get_file_content_rhv,
            mock_filepath_rhv,
            "RHV",
            id="RHV",
        ),
        pytest.param(
            mock_get_file_content_rhev,
            mock_filepath_rhev,
            "RHEV",
            id="RHEV",
        ),
        pytest.param(
            mock_get_file_content_vmware,
            mock_filepath_product_name,
            "VMware",
            id="VMware",
        ),
        pytest.param(
            mock_get_file_content_openstack,
            mock_filepath_product_name,
            "openstack",
            id="OpenStack",
        ),
        pytest.param(
            mock_get_file_content_xen_bios_vendor,
            mock_filepath_bios_vendor,
            "xen",
            id="Xen",
        ),
        pytest.param(
            mock_get_file_content_virtualbox,
            mock_filepath_bios_vendor,
            "virtualbox",
            id="VirtualBox",
        ),
        pytest.param(
            mock_get_file_content_nutanix,
            mock_filepath_sys_vendor,
            "kvm",
            id="Nutanix",
        ),
        pytest.param(
            mock_get_file_content_kubevirt,
            mock_filepath_sys_vendor,
            "KubeVirt",
            id="KubeVirt",
        ),
        pytest.param(
            mock_get_file_content_microsoft,
            mock_filepath_sys_vendor,
            "VirtualPC",
            id="VirtualPC",
        ),
        pytest.param(
            mock_get_file_content_parallel,
            mock_filepath_sys_vendor,
            "parallels",
            id="Parallels",
        ),
        pytest.param(
            mock_get_file_content_openstack_sys,
            mock_filepath_sys_vendor,
            "openstack",
            id="OpenStack Foundation",
        ),
    ],
)
def test_get_virtual_facts_guest(mocker, mock_method, mock_filepath_method, expected_hypervisor):
    mocker.patch("os.path.exists", side_effect=mock_filepath_method)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_content",
        side_effect=mock_method,
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "guest",
        "virtualization_tech_guest": set([expected_hypervisor]),
        "virtualization_type": expected_hypervisor,
        "virtualization_tech_host": set(),
    }
    assert facts == expected


def test_get_virtual_facts_linux_vserver_guest(mocker):
    mocker.patch("os.path.exists", side_effect=mock_proc_self_status)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_lines",
        side_effect=mock_get_file_lines_linuxvserver_guest,
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "guest",
        "virtualization_tech_guest": set(["linux_vserver"]),
        "virtualization_type": "linux_vserver",
        "virtualization_tech_host": set(),
    }
    assert facts == expected


def test_get_virtual_facts_linux_vserver_host(mocker):
    mocker.patch("os.path.exists", side_effect=mock_proc_self_status)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_lines",
        side_effect=mock_get_file_lines_linuxvserver_host,
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "host",
        "virtualization_tech_guest": set(),
        "virtualization_type": "linux_vserver",
        "virtualization_tech_host": set(["linux_vserver"]),
    }
    assert facts == expected


@pytest.mark.parametrize(
    ("mock_proc_cpuinfo_method", "expected_role", "expected_value"),
    (
        pytest.param(
            mock_get_file_lines_proc_cpuinfo_qemu,
            "guest",
            "kvm",
            id="QEMU",
        ),
        pytest.param(
            mock_get_file_lines_proc_cpuinfo_uml,
            "guest",
            "uml",
            id="User-Mode-Linux",
        ),
        pytest.param(
            mock_get_file_lines_proc_cpuinfo_uml,
            "guest",
            "uml",
            id="User-Mode-Linux-model-name",
        ),
        pytest.param(
            mock_get_file_lines_proc_cpuinfo_ibm,
            "guest",
            "kvm",
            id="IBM",
        ),
        pytest.param(
            mock_get_file_lines_proc_cpuinfo_powervm,
            "guest",
            "powervm_lx86",
            id="PowerVM-LX86",
        ),
        pytest.param(
            mock_get_file_lines_proc_cpuinfo_ibms390,
            "LPAR",
            "PR/SM",
            id="IBM-S390",
        ),
    ),
)
def test_get_virtual_facts_proc_cpuinfo(
    mocker, mock_proc_cpuinfo_method, expected_role, expected_value
):
    mocker.patch("os.path.exists", side_effect=mock_proc_cpuinfo)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_lines",
        side_effect=mock_proc_cpuinfo_method,
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": expected_role,
        "virtualization_tech_guest": set([expected_value]),
        "virtualization_type": expected_value,
        "virtualization_tech_host": set(),
    }
    assert facts == expected


@pytest.mark.parametrize(
    ("mock_proc_modules_method", "expected_role", "expected_value"),
    [
        pytest.param(
            mock_get_file_lines_proc_modules_kvm,
            "host",
            "kvm",
            id="KVM",
        ),
        pytest.param(
            mock_get_file_lines_proc_modules_virtualbox,
            "host",
            "virtualbox",
            id="VirtualBox",
        ),
        pytest.param(
            mock_get_file_lines_proc_modules_virtio,
            "guest",
            "kvm",
            id="virtio",
        ),
    ],
)
def test_get_virtual_facts_proc_modules(
    mocker, mock_proc_modules_method, expected_role, expected_value
):
    mocker.patch("os.path.exists", side_effect=mock_proc_modules)
    mocker.patch("os.access", side_effect=mock_proc_modules)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_lines",
        side_effect=mock_proc_modules_method,
    )
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": expected_role,
        "virtualization_tech_guest": set(),
        "virtualization_type": expected_value,
        "virtualization_tech_host": set([expected_value]),
    }
    assert facts == expected


@pytest.mark.parametrize(
    ("mock_output", "virtualization_type"),
    [
        pytest.param(
            "BHYVE\n",
            "bhyve",
            id="BHYVE",
        ),
        pytest.param(
            "VMware\n",
            "VMware",
            id="VMware",
        ),
    ],
)
def test_get_virtual_facts_bhyve(mocker, mock_output, virtualization_type):
    mocker.patch("os.path.exists", return_value=False)
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_content", return_value=""
    )
    mocker.patch(
        "ansible.module_utils.facts.virtual.linux.get_file_lines", return_value=[]
    )

    module = mocker.Mock()
    module.run_command.return_value = (0, mock_output, "")
    inst = linux.LinuxVirtual(module)

    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "guest",
        "virtualization_tech_host": set(),
        "virtualization_type": virtualization_type,
        "virtualization_tech_guest": set([virtualization_type]),
    }

    assert facts == expected


def test_get_virtual_facts_dev_kvm(mocker):
    mocker.patch("os.path.exists", side_effect=mock_dev_kvm)
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "host",
        "virtualization_tech_guest": set(),
        "virtualization_type": "kvm",
        "virtualization_tech_host": set(["kvm"]),
    }
    assert facts == expected


def test_get_virtual_facts_na(mocker):
    mocker.patch("os.path.exists", return_value=False)
    module = mocker.Mock()
    module.run_command.return_value = (0, "", "")
    inst = linux.LinuxVirtual(module)
    facts = inst.get_virtual_facts()
    expected = {
        "virtualization_role": "NA",
        "virtualization_tech_guest": set(),
        "virtualization_type": "NA",
        "virtualization_tech_host": set(),
    }
    assert facts == expected
