import os
import pathlib
import json
import subprocess
import hashlib
import shutil
import sys
from colorama import Fore,Back,init

vboxmanage_sha256 = "e058bc8a9bf9b8cf81b58efd18c16ae563d08b9641aea4732b336a0d619b7294"

init()


def check_if_hosts_exists():
    known_hosts_directory = pathlib.Path(os.getenv("USERPROFILE", os.getenv("HOME", ""))).joinpath(".ssh").joinpath("known_hosts")
    if not os.path.exists(known_hosts_directory):
        print(Fore.RED + "[-] Failed to find the known_hosts file. Please ensure that you have connected to the VM at least once before running this script." + Fore.RESET)
        sys.exit(1)


def shutdown_vm():
    if  not is_vm_running(False):
        print(Fore.RED + "[-] VM is already not running" + Fore.WHITE)
        return False
    print(Fore.CYAN + "Shutting down the Qiling VM" + Fore.WHITE)
    shutdown_command = subprocess.run(["VBoxManage","controlvm",]) 

def check_vboxmanage_digest():
    vboxmanage_path = shutil.which("VBoxManage")
    print(Fore.GREEN + "Virtual Box Path: {}".format(vboxmanage_path)+ Fore.WHITE)
    if not vboxmanage_path:
        print(Fore.RED + "[-] VBoxManage is not available in the system PATH. Please ensure that VirtualBox is installed and VBoxManage is in your PATH." + Fore.RESET)
        return False
    if os.path.getsize(vboxmanage_path) == 0:
        print(Fore.RED + "[-] VboxManage binary is empty. Please ensure that VirtualBox is installed correctly." + Fore.RESET)
        return False
    print(Fore.CYAN + "Calculating the Digest of the Virtual Box Terminal" + Fore.WHITE)
    VboxManage_digest = ""
    with open(vboxmanage_path, "rb") as f:
        VboxManage_digest = hashlib.sha256(f.read()).hexdigest()
        print(Fore.GREEN + "HexDigest : {}".format(VboxManage_digest) + Fore.WHITE) 
    if not VboxManage_digest:
        print(Fore.RED + "[-] Failed to calculate the SHA256 digest of VBoxManage. Please ensure that VirtualBox is installed correctly." + Fore.RESET)
        return False
    if VboxManage_digest != vboxmanage_sha256:
        print(Fore.RED + "[-] The SHA256 digest of VBoxManage does not match the expected value. Please ensure that you are using the correct version of VirtualBox." + Fore.RESET)
        return False
    print(Fore.GREEN + "[+] The SHA256 digest of VBoxManage matches the expected value" + Fore.WHITE)
    return True 

def check_if_vboxmanage_exists():
    print("[+] Checking if VBoxManage is available in the system PATH...")
    if not shutil.which("VBoxManage"):
        print(Fore.RED + "[-] VBoxManage is not available in the system PATH. Please ensure that VirtualBox is installed and VBoxManage is in your PATH." + Fore.RESET)
        sys.exit(1)
    print(Fore.GREEN + "[+] VBoxManage is available in the system PATH." + Fore.RESET)
    return True

def is_vm_running(start_vm: bool = False) -> bool:
    info = load_vm_info()
    print(Fore.GREEN  + "[+] Checking if the Qiling VM is running..." + Fore.WHITE)
    vm_name = info.get("VM_NAME")
    if not vm_name:
        print(Fore.RED + "[-] VM_NAME not found in vm_info.json. Please ensure that the file is correctly formatted." + Fore.RESET)
        sys.exit(1)
    is_it_running = subprocess.run(["VBoxManage", "list", "runningvms"], capture_output=True, text=True)
    if is_it_running.returncode != 0:
        print(Fore.RED + "[-] Failed to check if the VM is running. Please ensure that VirtualBox is installed and VBoxManage is in your PATH." + Fore.RESET)
        sys.exit(1)
    found = False
    stdout = is_it_running.stdout.strip()
    for i in stdout.split():
        if i.find(vm_name) != -1:
            print(Fore.GREEN + "[+] The Qiling VM is running." + Fore.WHITE)
            found = True
    if found:
        print(Fore.GREEN + "[+] The Qiling VM is running." + Fore.WHITE)
        return True
    else:
        print(Fore.RED + "[-] The Qiling VM is not running." + Fore.RESET)
        if not start_vm:
            print(Fore.YELLOW + "[!] run_vm flag is set off , not starting the script." + Fore.RESET) 
            return False
        run_vm = subprocess.run(["VBoxManage", "startvm", vm_name, "--type", "headless"], capture_output=True, text=True)
        if run_vm.returncode != 0:
            print(Fore.RED + "[-] Failed to start the VM. Please ensure that VirtualBox is installed and VBoxManage is in your PATH." + Fore.RESET)
            return False
        print(Fore.GREEN + "[+] The Qiling VM has been started." + Fore.WHITE)
        return True

def stop_vm():
    if not is_vm_running():
        print(Fore.RED + "[-] The Qiling VM is not running. Cannot stop a VM that is not running." + Fore.RESET)
        return False
    info = load_vm_info()
    vm_name = info.get("VM_NAME")
    stop_vm = subprocess.run(["VBoxManage", "controlvm", vm_name, "poweroff"], capture_output=True, text=True)
    if stop_vm.returncode != 0:
        print(Fore.RED + "[-] Failed to stop the VM. Please ensure that VirtualBox is installed and VBoxManage is in your PATH." + Fore.RESET)
        return False
    print(Fore.GREEN + "[+] The Qiling VM has been stopped." + Fore.WHITE)
    return True

def load_vm_info() -> dict:
    file_dict = {}
    filepath = pathlib.Path(__file__).parent.joinpath("vm_info.json").resolve()
    print(Fore.GREEN + "[+] Checking if the Qiling VM is available..." + Fore.WHITE)
    if not os.path.exists(str(filepath)):
        print(Fore.RED + "[-] Failed to find the vm_info.json file. Please ensure that the file exists in the qiling_dlls directory." + Fore.RESET)
        sys.exit(1)
    print(Fore.GREEN + "[+] Found the VM INFO..." + Fore.WHITE)
    with open(filepath, "r") as f:
        try:
            content = f.read()
            print(Fore.CYAN + "[+] vm_info.json parameter : \n {}".format(content) + Fore.WHITE)
            file_dict  = json.loads(content)
        except json.JSONDecodeError as e:
            print(Fore.RED + f"[-] Failed to parse the vm_info.json file: {e}" + Fore.RESET)
            sys.exit(0)
    print(Fore.GREEN + "[+] Testing VM IP: {}".format(file_dict["VM_IP"]) + Fore.WHITE)
    return file_dict

    

def does_qiling_vm_exists():
    l = load_vm_info()
    vm_name = l.get("VM_NAME")
    if not vm_name:
        print(Fore.RED + "[-] Please setup the name of the Virtual Machine in the vm_info.json file" + Fore.WHITE)
        return False
    sub_command = subprocess.run(["VBoxManage","list","vms"],text=True,capture_output=True)
    if sub_command.returncode != 0:
        print(Fore.RED + "[-] Failed to exectue the required command..." + Fore.WHITE)
        return False
    output = sub_command.stdout.strip()
    for i in output.split(" "):
        if i.find(vm_name) != -1:
            print(Fore.GREEN + "[+] Qiling VM Has been found Succesfully" + Fore.WHITE)
            return True
    print(Fore.RED + "[-] Check if the VM is Installed Correctlty" + Fore.WHITE)
    return False

def  check_vm_connection(hostname, username, password):
    """
    Check the connection to a virtual machine using SSH.

    :param hostname: The hostname or IP address of the VM.
    :param username: The username to use for SSH authentication.
    :param password: The password to use for SSH authentication.
    :return: True if the connection is successful, False otherwise.
    """
    try:
       
        client = paramiko.SSHClient()
        
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password)
        client.close()
        return True
    except Exception as e:
        print(f"Connection failed: {e}")
        return False
    
def should_run_or_not():
    print(Fore.CYAN + f"{'#' * 6} QILING Machine Verification f{'#' * 6}" + Fore.WHITE)
    print(Fore.CYAN + f"Checking if the VBoxManage Utility Exists" + Fore.WHITE)
    vbox_exists = check_if_vboxmanage_exists()
    if not vbox_exists:
        print(Fore.RED + "Failed to find Vbox Manage executable do you have VirtualBox Intsalled ?" + Fore.WHITE)
        return False
    print(Fore.CYAN + "Checking if the Digest of VBoxManage is Valid" + Fore.WHITE)
    digest_check = check_vboxmanage_digest()
    if not digest_check:
        print(Fore.RED + "[-] Mismatched Digest... Check if you have installed the right Virtual Box Tool" + Fore.WHITE)
        return False
    print(Fore.CYAN + "Checking if VM Exists..."+ Fore.WHITE)
    existance_check = does_qiling_vm_exists() 
    if not existance_check:
        print(Fore.RED + "[-] Qiling VM was not found..." + Fore.WHITE) 
        return False
    print(Fore.CYAN + "[+] Is the  VM Running or not" + Fore.WHITE)
    run_check = is_vm_running(False)
    if not run_check:
        print(Fore.RED + "[-] VM is not running" + Fore.WHITE)
        return False
    print(Fore.CYAN + "[]") 
if __name__ == "__main__":
    should_run_or_not() 