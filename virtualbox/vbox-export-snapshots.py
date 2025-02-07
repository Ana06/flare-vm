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
import sys

from vboxcommon import LONG_WAIT, ensure_vm_running, export_vm, get_vm_uuid, restore_snapshot, set_network_to_hostonly

DESCRIPTION = """Export a snapshot as .ova, changing the network to a single Host-Only interface.
Generate a file with the SHA256 of the exported OVA(s)."""

EPILOG = """
Example usage:
  # Export snapshots using the information in the "configs/export_win10_flare-vm.json" config file
  ./vbox-export-snapshots.py configs/export_win10_flare-vm.json
"""

# Duration of the power cycle: the seconds we wait between starting the VM and powering it off.
# It should be long enough for the internet_detector to detect the network change.
POWER_CYCLE_TIME = 240  # 4 minutes


def export_snapshot(vm_uuid, snapshot, description, export_dir_name):
    """Restore a snapshot, set the network to hostonly and then export it with the snapshot as name."""
    try:
        restore_snapshot(vm_uuid, snapshot)

        set_network_to_hostonly(vm_uuid)

        # Do a power cycle to ensure everything is good and
        # give the internet detector time to detect the network change
        print(f"VM {vm_uuid} 🔄 power cycling before export{LONG_WAIT}")
        ensure_vm_running(vm_uuid)
        export_vm(vm_uuid, snapshot, description, export_dir_name)
    except Exception as e:
        print(f'VM {vm_uuid} ❌ ERROR exporting "{snapshot}":{e}\n')


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("vm_name", help="name of the VM to export snapshot from.")
    parser.add_argument("snapshot", help="name of the snapshot to export.")
    parser.add_argument("--description", help="description of the exported OVA. Empty by default.")
    parser.add_argument(
        "--export_dir_name",
        help="name of the directory in HOME to export the VMs The directory is created if it does not exist. Default: {EXPORTED_DIR_NAME}",
    )
    args = parser.parse_args(args=argv)

    vm_uuid = get_vm_uuid(args.vm_name)
    if not vm_uuid:
        print(f'❌ ERROR: "{args.vm_name}" not found')
        exit()

    print(f'\nExporting snapshot "{args.snapshot}" from "{args.vm_name}" {vm_uuid}...')
    export_snapshot(vm_uuid, args.snapshot, args.description, args.export_dir_name)


if __name__ == "__main__":
    main()
