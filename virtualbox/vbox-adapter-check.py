#!/usr/bin/python3
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import argparse
import re
import sys
import textwrap

import gi

from vboxcommon import ensure_hostonlyif_exists, get_vm_state, run_vboxmanage

gi.require_version("Notify", "0.7")
from gi.repository import Notify  # noqa: E402

DYNAMIC_VM_NAME = ".dynamic"
DISABLED_ADAPTER_TYPE = "hostonly"
ALLOWED_ADAPTER_TYPES = ("hostonly", "intnet", "none")

DESCRIPTION = f"""Print the status of all internet adapters of all VMs in VirtualBox.
Notify if any VM with {DYNAMIC_VM_NAME} in the name has an adapter whose type is not allowed.
This is useful to detect internet access which is undesirable for dynamic malware analysis.
Optionally change the type of the adapters with non-allowed type to Host-Only."""

EPILOG = textwrap.dedent(
    f"""
    Example usage:
      # Print status of all interfaces and disable internet access in VMs whose name contain {DYNAMIC_VM_NAME}
      vbox-adapter-check.vm

      # Print status of all interfaces without modifying any of them
      vbox-adapter-check.vm --do_not_modify
    """
)


def get_vm_uuids(dynamic_only):
    """Gets the machine UUID(s) for a given VM name using 'VBoxManage list vms'."""
    vm_uuids = []
    try:
        # regex VM name and extract the GUID
        # "FLARE-VM.testing" {b76d628b-737f-40a3-9a16-c5f66ad2cfcc}
        vms_info = run_vboxmanage(["list", "vms"])
        pattern = r'"(.*?)" \{(.*?)\}'
        matches = re.findall(pattern, vms_info)
        for match in matches:
            vm_name = match[0]
            vm_uuid = match[1]
            # either get all vms if dynamic_only false, or just the dynamic vms if true
            if (not dynamic_only) or DYNAMIC_VM_NAME in vm_name:
                vm_uuids.append((vm_name, vm_uuid))
    except Exception as e:
        raise Exception("Error finding machines UUIDs") from e
    return vm_uuids


def change_network_adapters_to_hostonly(vm_uuid, vm_name, hostonly_ifname, do_not_modify):
    """Verify all adapters are in an allowed configuration. Must be poweredoff"""
    try:
        # gather adapters in incorrect configurations
        nics_with_internet = []
        invalid_nics_msg = ""

        # nic1="hostonly"
        # nictype1="82540EM"
        # nicspeed1="0"
        # nic2="none"
        # nic3="none"
        # nic4="none"
        # nic5="none"
        # nic6="none"
        # nic7="none"
        # nic8="none"

        vminfo = run_vboxmanage(["showvminfo", vm_uuid, "--machinereadable"])
        for nic_number, nic_value in re.findall(r'^nic(\d+)="(\S+)"', vminfo, flags=re.M):
            if nic_value not in ALLOWED_ADAPTER_TYPES:
                nics_with_internet.append(f"nic{nic_number}")
                invalid_nics_msg += f"{nic_number} "

        # modify the invalid adapters if allowed
        if nics_with_internet:
            for nic in nics_with_internet:
                if do_not_modify:
                    message = f"{vm_name} may be connected to the internet on adapter(s): {nic}. Please double check your VMs settings."
                else:
                    message = (
                        f"{vm_name} may be connected to the internet on adapter(s): {nic}."
                        "The network adapter(s) have been disabled automatically to prevent an undesired internet connectivity."
                        "Please double check your VMs settings."
                    )
                    # different commands are necessary if the machine is running.
                    if get_vm_state(vm_uuid) == "poweroff":
                        run_vboxmanage(
                            [
                                "modifyvm",
                                vm_uuid,
                                f"--{nic}",
                                DISABLED_ADAPTER_TYPE,
                            ]
                        )
                    else:
                        run_vboxmanage(
                            [
                                "controlvm",
                                vm_uuid,
                                nic,
                                "hostonly",
                                hostonly_ifname,
                            ]
                        )
                    print(f"Set VM {vm_name} adaper {nic} to hostonly")

            if do_not_modify:
                message = f"{vm_name} may be connected to the internet on adapter(s): {invalid_nics_msg}. Please double check your VMs settings."
            else:
                message = (
                    f"{vm_name} may be connected to the internet on adapter(s): {invalid_nics_msg}."
                    "The network adapter(s) have been disabled automatically to prevent an undesired internet connectivity."
                    "Please double check your VMs settings."
                )

            # Show notification using PyGObject
            Notify.init("VirtualBox adapter check")
            notification = Notify.Notification.new(f"INTERNET IN VM: {vm_name}", message, "dialog-error")
            # Set highest priority
            notification.set_urgency(2)
            notification.show()
            print(f"{vm_name} network configuration not ok, sent notifaction")
            return
        else:
            print(f"{vm_name} network configuration is ok")
            return

    except Exception as e:
        raise Exception("Failed to verify VM adapter configuration") from e


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--do_not_modify",
        action="store_true",
        help="Only print the status of the internet adapters without modifying them.",
    )
    parser.add_argument(
        "--dynamic_only",
        action="store_true",
        help="Only scan VMs with .dynamic in the name",
    )
    args = parser.parse_args(args=argv)

    try:
        hostonly_ifname = ensure_hostonlyif_exists()
        vm_uuids = get_vm_uuids(args.dynamic_only)
        if len(vm_uuids) > 0:
            for vm_name, vm_uuid in vm_uuids:
                change_network_adapters_to_hostonly(vm_uuid, vm_name, hostonly_ifname, args.do_not_modify)
        else:
            print("[Warning ⚠️] No VMs found")
    except Exception as e:
        print(f"Error verifying dynamic VM hostonly configuration: {e}")


if __name__ == "__main__":
    main()
