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
import sys
import textwrap
import time
from datetime import datetime

import yaml

from vboxcommon import (
    LONG_WAIT,
    ensure_vm_running,
    ensure_vm_shutdown,
    export_vm,
    get_vm_uuid,
    restore_snapshot,
    run_vboxmanage,
    set_network_to_hostonly,
)

DESCRIPTION = textwrap.dedent(
    """
    Restore a `BUILD-READY` snapshot, copy files required for the installation
    (like the IDA Pro installer and the FLARE-VM configuration file) and installs FLARE-VM.
    After the installation completes, create several snapshots and export every of them as OVA.
    Require a configuration file.
    """
)

EPILOG = """
Example usage:
  # Build FLARE-VM and export several OVAs using the information in the provided configuration file, using '19930906' as date
  #./vbox-build-vm.py configs/win10_flare-vm.yaml --custom_config --date='19930906'
"""

# The base snapshot is expected to be an empty Windows installation that satisfies the FLARE-VM installation requirements and has UAC disabled
# To disable UAC execute in a cmd console with admin rights and restart the VM for the change to take effect:
# %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
BASE_SNAPSHOT = "BUILD-READY"

# Guest username and password, needed to execute commands in the guest
GUEST_USERNAME = "flare"
GUEST_PASSWORD = "password"

# Logs
LOGS_DIR = os.path.expanduser("~/FLARE-VM LOGS")
LOG_FILE_GUEST = r"C:\ProgramData\_VM\log.txt"
LOG_FILE_HOST = rf"{LOGS_DIR}/flare-vm-log.txt"
FAILED_PACKAGES_GUEST = r"C:\ProgramData\_VM\failed_packages.txt"
FAILED_PACKAGES_HOST = rf"{LOGS_DIR}/flare-vm-failed_packages.txt"

# Required files
REQUIRED_FILES_DIR = os.path.expanduser("~/FLARE-VM REQUIRED FILES")
REQUIRED_FILES_DEST = rf"C:\Users\{GUEST_USERNAME}\Desktop"

# Executable paths in guest
POWERSHELL_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD_PATH = r"C:\Windows\System32\cmd.exe"

# Cleanup command to be executed in cmd to delete the PowerShel logs
CMD_CLEANUP_CMD = r'/c rmdir /s /q %UserProfile%\Desktop\PS_Transcripts'


def control_guest(vm_uuid, args, real_time=False):
    """Run a 'VBoxManage guestcontrol' command providing the username and password.
    Args:
        vm_uuid: VM UUID
        args: list of arguments starting with the guestcontrol sub-command
        real_time: Boolean that determines if displaying the output in realtime or returning it.
    """
    # VM must be running to control the guest
    ensure_vm_running(vm_uuid)
    return run_vboxmanage(
        ["guestcontrol", vm_uuid, f"--username={GUEST_USERNAME}", f"--password={GUEST_PASSWORD}"] + args, real_time
    )


def run_command(vm_uuid, cmd, executable="PS"):
    """Run a command in the guest displaying the output in real time."""
    ensure_vm_running(vm_uuid)

    exe_path = POWERSHELL_PATH if executable == "PS" else CMD_PATH

    print(f"VM {vm_uuid} 🚧 {executable}: {cmd}")
    try:
        control_guest(vm_uuid, ["run", exe_path, cmd], True)
    except RuntimeError:
        raise RuntimeError("VM {vm_uuid} ❌ Command execution failed!")


def take_snapshot(vm_uuid, snapshot_name, shutdown=False):
    """Take a snapshot with the given name in the given VM, optionally shutting down the VM before."""
    if shutdown:
        ensure_vm_shutdown(vm_uuid)

    run_vboxmanage(["snapshot", vm_uuid, "take", snapshot_name])
    print(f'VM {vm_uuid} 📷 took snapshot "{snapshot_name}"')


def create_log_folder():
    """Ensure log folder exists and is empty."""
    # Create directory if it does not exist
    os.makedirs(LOGS_DIR, exist_ok=True)
    print(f"Log folder: {LOGS_DIR}\n")

    # Remove all files in the logs directory. Note the directory only files (the logs).
    for file in os.listdir(LOGS_DIR):
        os.remove(file)


def install_flare_vm(vm_uuid, wip_snapshot_name, custom_config):
    """Install FLARE-VM"""
    additional_arg = r"-customConfig '$desktop\config.xml'" if custom_config else ""
    flare_vm_installation_cmd = rf"""
    $desktop=[Environment]::GetFolderPath("Desktop")
    cd $desktop
    Set-ExecutionPolicy Unrestricted -Force
    $url="https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1"
    $file = "$desktop\install.ps1"
    (New-Object net.webclient).DownloadFile($url,$file)
    Unblock-File .\install.ps1

    start powershell "$file -password password -noWait -noGui -noChecks {additional_arg}"
    """
    run_command(vm_uuid, flare_vm_installation_cmd)
    print(f"VM {vm_uuid} ✅ FLARE-VM is being installed...{LONG_WAIT}")

    index = 0
    while True:
        time.sleep(60)  # Wait 1 minute
        try:
            control_guest(vm_uuid, ["copyfrom", f"--target-directory={FAILED_PACKAGES_HOST}", FAILED_PACKAGES_GUEST])
            break
        except RuntimeError:
            index += 1
            if (index % 10) == 0:  # Take a snapshot and print a message every 10 minutes
                time_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                print(f"VM {vm_uuid} 🕑 {time_str} still waiting")
                snapshot_name = f"WIP {wip_snapshot_name} {time_str}"
                take_snapshot(vm_uuid, snapshot_name)

    control_guest(vm_uuid, ["copyfrom", f"--target-directory={LOG_FILE_HOST}", LOG_FILE_GUEST])
    print(f"VM {vm_uuid} ✅ FLARE-VM installed!")

    # Read failed packages from log file and print them.
    # TODO: Research why file is empty or not accessible some times.
    try:
        if os.path.getsize(FAILED_PACKAGES_HOST):
            print("  ❌ FAILED PACKAGES")
            with open(FAILED_PACKAGES_HOST, "w") as f:
                failed_packages = f.read()
                for failed_package in failed_packages:
                    print(f"     - {failed_package}")
    except Exception:
        print(f"  ❌ Reading {FAILED_PACKAGES_HOST} failed")


def build_vm(vm_name, exported_vm_name, snapshots, date, custom_config):
    """"""
    vm_uuid = get_vm_uuid(vm_name)
    if not vm_uuid:
        print(f'❌ ERROR: "{vm_name}" not found')
        exit()

    print(f'\nGetting the installation VM "{vm_name}" {vm_uuid} ready...')
    create_log_folder()

    restore_snapshot(vm_uuid, BASE_SNAPSHOT)

    control_guest(vm_uuid, ["copyto", "--recursive", f"--target-directory={REQUIRED_FILES_DEST}", REQUIRED_FILES_DIR])
    print(f"VM {vm_uuid} 📁 Copied required files in: {REQUIRED_FILES_DIR}")

    install_flare_vm(vm_uuid, exported_vm_name, custom_config)

    base_snapshot_name = f"{exported_vm_name}.{date}.base"
    take_snapshot(vm_uuid, base_snapshot_name)

    for snapshot in snapshots:
        restore_snapshot(vm_uuid, base_snapshot_name)

        # Run snapshot configured command
        cmd = snapshot.get("cmd", None)
        if cmd:
            run_command(vm_uuid, cmd)

        set_network_to_hostonly(vm_uuid)

        # Set snapshot configured legal notice
        notice_file_name = snapshot.get("legal_notice", None)
        if notice_file_name:
            notice_file_path = rf"C:\Users\{GUEST_USERNAME}\Desktop\{notice_file_name}"
            set_notice_cmd = f"VM-Set-Legal-Notice (Get-Content  '{notice_file_path}' -Raw)"
            run_command(vm_uuid, set_notice_cmd)

        # Perform clean up: run 'VM-Clean-Up' excluding configured files and folders
        ps_cleanup_cmd = "VM-Clean-Up"
        excluded_files = snapshot.get("excluded_files", None)
        if excluded_files:
            ps_cleanup_cmd += f" -excludeFiles {excluded_files}"
        excluded_folders = snapshot.get("excluded_folders", None)
        if excluded_folders:
            f" -excludeFolders {excluded_folders}"
        run_command(vm_uuid, ps_cleanup_cmd)

        # Perform clean up: delete PowerShells logs (using cmd.exe)
        run_command(vm_uuid, CMD_CLEANUP_CMD, "CMD")

        # Take snapshot and export it with the configured description
        snapshot_name = f"{exported_vm_name}.{date}{snapshot['extension']}"
        take_snapshot(vm_uuid, snapshot_name, True)
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
        "--custom_config",
        action="store_true",
        default=False,
        help=f"flag to use a custom configuration file (expected to be in {REQUIRED_FILES_DIR}) for the FLARE-VM installation.",
    )
    parser.add_argument(
        "--date",
        help="Date to include in the snapshots and the exported VMs in YYMMDD format. Today's date by default.",
        default=datetime.today().strftime("%Y%m%d"),
    )
    args = parser.parse_args(args=argv)

    try:
        with open(args.config_path) as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f'Invalid "{args.config_path}": {e}')
        exit()

    build_vm(config["VM_NAME"], config["EXPORTED_VM_NAME"], config["SNAPSHOTS"], args.date, args.custom_config)


if __name__ == "__main__":
    main()
