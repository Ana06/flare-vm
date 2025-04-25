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
import os
import re
import sys
import time
from datetime import datetime

import yaml
from vboxcommon import (
    LONG_WAIT,
    ensure_vm_running,
    ensure_vm_shutdown,
    export_vm,
    get_vm_state,
    get_vm_uuid,
    restore_snapshot,
    run_vboxmanage,
    set_network_to_hostonly,
)

DESCRIPTION = """
Automates the creation and export of customized REMnux virtual machines (VMs).
Begins by restoring a pre-existing "BUILD-READY" snapshot of a clean REMnux OVA.
Required installation files (such as the IDA Pro installer) are then copied into the guest VM.
The configuration file specifies the VM name, the exported VM name, and details for each snapshot.
Individual snapshot configurations include the extension, description, and custom commands to be executed within the guest.
"""

EPILOG = """
Example usage:
  #./vbox-build-remnux.py configs/remnux.yaml --date='19930906'
"""

BASE_SNAPSHOT = "BUILD-READY"

# Guest username and password, needed to execute commands in the guest
GUEST_USERNAME = "remnux"
GUEST_PASSWORD = "malware"

# Required files
REQUIRED_FILES_DIR = os.path.expanduser("~/REMNUX REQUIRED FILES")
REQUIRED_FILES_DEST = rf"/home/{GUEST_USERNAME}/Desktop"


def control_guest(vm_uuid, args, real_time=False):
    """Run a 'VBoxManage guestcontrol' command providing the username and password.
    Args:
        vm_uuid: VM UUID
        args: list of arguments starting with the guestcontrol sub-command
        real_time: Boolean that determines if displaying the output in realtime or returning it.
    """
    # VM must be running to control the guest
    ensure_vm_running(vm_uuid)
    cmd = ["guestcontrol", vm_uuid, f"--username={GUEST_USERNAME}", f"--password={GUEST_PASSWORD}"] + args
    try:
        return run_vboxmanage(cmd, real_time)
    except RuntimeError:
        # The guest additions take a bit to load after the user is logged in
        # In slow environments this may cause the command to fail, wait a bit and re-try
        time.sleep(120)  # Wait 2 minutes
        return run_vboxmanage(cmd, real_time)


def run_command(vm_uuid, cmd):
    """Run a command in the guest displaying the output in real time."""
    ensure_vm_running(vm_uuid)

    executable = "/bin/sh"
    print(f"VM {vm_uuid} 🚧 {executable}: {cmd}")
    control_guest(vm_uuid, ["run", executable, cmd], True)


def take_snapshot(vm_uuid, snapshot_name, shutdown=False):
    """Take a snapshot with the given name in the given VM, optionally shutting down the VM before."""
    if shutdown:
        ensure_vm_shutdown(vm_uuid)

    # Take a base snapshot, ensuring there is no snapshot with the same name
    rename_old_snapshot(vm_uuid, snapshot_name)
    run_vboxmanage(["snapshot", vm_uuid, "take", snapshot_name])
    print(f'VM {vm_uuid} 📷 took snapshot "{snapshot_name}"')


def rename_old_snapshot(vm_uuid, snapshot_name):
    """Append 'OLD' to the name of the snapshots with the given name"""
    # Example of 'VBoxManage snapshot VM_NAME list --machinereadable' output:
    # SnapshotName="ROOT"
    # SnapshotUUID="86b38fc9-9d68-4e4b-a033-4075002ab570"
    # SnapshotName-1="Snapshot 1"
    # SnapshotUUID-1="e383e702-fee3-4e0b-b1e0-f3b869dbcaea"
    snapshots_info = run_vboxmanage(["snapshot", vm_uuid, "list", "--machinereadable"])

    # Find how many snapshots have the given name and edit a snapshot with that name as many times
    snapshots = re.findall(rf'^SnapshotName(-\d+)*="{snapshot_name}"\n', snapshots_info, flags=re.M)
    for _ in range(len(snapshots)):
        run_vboxmanage(["snapshot", vm_uuid, "edit", snapshot_name, f"--name='{snapshot_name} OLD"])


def build_vm(vm_name, exported_vm_name, snapshots, date):
    """"""
    vm_uuid = get_vm_uuid(vm_name)
    if not vm_uuid:
        print(f'❌ ERROR: "{vm_name}" not found')
        exit()

    print(f'\nGetting the installation VM "{vm_name}" {vm_uuid} ready...')

    for snapshot in snapshots:
        restore_snapshot(vm_uuid, BASE_SNAPSHOT)

        control_guest(
            vm_uuid, ["copyto", "--recursive", f"--target-directory={REQUIRED_FILES_DEST}", REQUIRED_FILES_DIR]
        )
        print(f"VM {vm_uuid} 📁 Copied required files in: {REQUIRED_FILES_DIR}")

        # Run snapshot configured command
        cmd = snapshot.get("cmd", None)
        if cmd:
            run_command(vm_uuid, cmd)

        set_network_to_hostonly(vm_uuid)

        # Take snapshot turning the VM off
        extension = snapshot.get("extension", "")
        snapshot_name = f"{exported_vm_name}.{date}{extension}"
        take_snapshot(vm_uuid, snapshot_name, True)

        # Export the snapshot with the configured description
        export_vm(vm_uuid, snapshot_name, snapshot.get("description", ""))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("config_path", help="path of the YAML configuration file.")
    parser.add_argument(
        "--date",
        help="Date to include in the snapshots and the exported VMs in YYYYMMDD format. Today's date by default.",
        default=datetime.today().strftime("%Y%m%d"),
    )
    args = parser.parse_args(args=argv)

    try:
        with open(args.config_path) as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f'Invalid "{args.config_path}": {e}')
        exit()

    build_vm(
        config["VM_NAME"],
        config["EXPORTED_VM_NAME"],
        config["SNAPSHOTS"],
        args.date,
    )


if __name__ == "__main__":
    main()
