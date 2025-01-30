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

"""
Export one or more snapshots in the same VirtualBox VM as .ova, changing the network adapter to Host-Only.
Generate a file with the SHA256 of the exported .ova.
The exported VM names start with "FLARE-VM.{date}".
"""

import hashlib
import os
import re
from datetime import datetime

from vboxcommon import *

# Base name of the exported VMs
EXPORTED_VM_NAME = "FLARE-VM"

# Name of the VM to export the snapshots from
VM_NAME = f"{EXPORTED_VM_NAME}.testing"

# Name of the directory in HOME to export the VMs
# The directory is created if it does not exist
EXPORT_DIR_NAME = "EXPORTED VMS"

# Array with snapshots to export as .ova where every entry is a tuple with the info:
# - Snapshot name
# - VM name extension (exported VM name: "FLARE-VM.<date>.<extension")
# - Exported VM description
SNAPSHOTS = [
    (
        "FLARE-VM",
        ".dynamic",
        "Windows 10 VM with FLARE-VM default configuration installed",
    ),
    (
        "FLARE-VM.full",
        ".full.dynamic",
        "Windows 10 VM with FLARE-VM default configuration + the packages 'visualstudio.vm' and 'pdbs.pdbresym.vm' installed",
    ),
    (
        "FLARE-VM.EDU",
        ".EDU",
        "Windows 10 VM with FLARE-VM default configuration installed + FLARE-EDU teaching materials",
    ),
]


def sha256_file(filename):
    with open(filename, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def get_vm_uuid(vm_name):
    """Get the machine UUID for a given VM name using 'VBoxManage list vms'. Return None if not found."""
    # regex VM name and extract the GUID
    # Example of `VBoxManage list vms` output:
    # "FLARE-VM.testing" {b76d628b-737f-40a3-9a16-c5f66ad2cfcc}
    # "FLARE-VM" {a23c0c37-2062-4cf0-882b-9e9747dd33b6}
    vms_info = run_vboxmanage(["list", "vms"])

    match = re.search(f'^"{vm_name}" (?P<uuid>\{{.*?\}})', vms_info, flags=re.M)
    if match:
        return match.group("uuid")


def change_network_adapters_to_hostonly(vm_uuid):
    """Changes all active network adapters to Host-Only. Must be poweredoff"""
    ensure_hostonlyif_exists()
    try:
        # disable all the nics to get to a clean state
        vminfo = run_vboxmanage(["showvminfo", vm_uuid, "--machinereadable"])
        for nic_number, nic_value in re.findall(
            '^nic(\d+)="(\S+)"', vminfo, flags=re.M
        ):
            if nic_value != "none":  # Ignore NICs with value "none"
                run_vboxmanage(["modifyvm", vm_uuid, f"--nic{nic_number}", "none"])
                print(f"Changed nic{nic_number}")

        # set first nic to hostonly
        run_vboxmanage(["modifyvm", vm_uuid, f"--nic1", "hostonly"])

        # ensure changes applied
        vminfo = run_vboxmanage(["showvminfo", vm_uuid, "--machinereadable"])
        for nic_number, nic_value in re.findall(
            '^nic(\d+)="(\S+)"', vminfo, flags=re.M
        ):
            if nic_number == "1" and nic_value != "hostonly":
                print("Invalid nic configuration detected, nic1 not hostonly")
                raise Exception(
                    "Invalid nic configuration detected, first nic not hostonly"
                )
            elif nic_number != "1" and nic_value != "none":
                print(
                    f"Invalid nic configuration detected, nic{nic_number} not disabled"
                )
                raise Exception(
                    f"Invalid nic configuration detected, nic{nic_number} not disabled"
                )
        print("Nic configuration verified correct")
        return
    except Exception as e:
        raise Exception("Failed to change VM network adapters to hostonly") from e


def restore_snapshot(vm_uuid, snapshot_name):
    status = run_vboxmanage(["snapshot", vm_uuid, "restore", snapshot_name])
    print(f"Restored '{snapshot_name}'")
    return status


if __name__ == "__main__":
    date = datetime.today().strftime("%Y%m%d")

    vm_uuid = get_vm_uuid(VM_NAME)
    if not vm_uuid:
        print(f'ERROR: "{VM_NAME}" not found')
        exit()

    print(f'Exporting snapshots from "{VM_NAME}" {vm_uuid}')
    for snapshot_name, extension, description in SNAPSHOTS:
        try:
            # Shutdown machine
            ensure_vm_shutdown(vm_uuid)

            # Restore snapshot (must be shutdown)
            restore_snapshot(vm_uuid, snapshot_name)

            # Shutdown machine (incase the snapshot was taken while running)
            ensure_vm_shutdown(vm_uuid)

            # change all adapters to hostonly (must be shutdown)
            change_network_adapters_to_hostonly(vm_uuid)

            # do a power cycle to ensure everything is good
            print("Power cycling before export...")

            # TODO: Add a guest notifier (read: run a script in the guest) to say when windows boots, only then shutdown.
            # this works right now but it's a hardcoded sleep which wasts time and isn't guaranteed to not race. Fine for now.
            ensure_vm_running(vm_uuid)
            ensure_vm_shutdown(vm_uuid)
            print("Power cycling done.")

            # Export .ova
            exported_vm_name = f"{EXPORTED_VM_NAME}.{date}{extension}"
            export_directory = os.path.expanduser(f"~/{EXPORT_DIR_NAME}")
            os.makedirs(export_directory, exist_ok=True)
            filename = os.path.join(export_directory, f"{exported_vm_name}.ova")

            print(f"Exporting {filename} (this will take some time, go for an 🍦!)")
            run_vboxmanage(
                [
                    "export",
                    vm_uuid,
                    f"--output={filename}",
                    "--vsys=0",  # We need to specify the index of the VM, 0 as we only export 1 VM
                    f"--vmname={exported_vm_name}",
                    f"--description={description}",
                ]
            )

            # Generate file with SHA256
            with open(f"{filename}.sha256", "w") as f:
                f.write(sha256_file(filename))

            print(f"Exported {filename}! 🎉")
        except Exception as e:
            print(f"Unexpectedly failed doing operations on {VM_NAME}, snapshot ({snapshot_name}).\n{e}")
            break
        print(f"All operations on {VM_NAME}, snapshot ({snapshot_name}), successful ✅")
    print("Done. Exiting...")
