import paramiko
import json
import requests
import os
import sys
import subprocess
import pathlib
from colorama import Fore,Back,init

init()

def run_as_admin(batch_file_path):
    """
    Execute the given batch file with administrator privileges.
    Uses PowerShell's Start-Process -Verb RunAs to trigger the UAC prompt.
    """
    try:
        ps_command = (
            f'Start-Process -FilePath "{batch_file_path}" '
            f'-Verb RunAs -Wait'
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            check=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Failed to run as admin: {e}" + Fore.WHITE)
        return False
    except Exception as e:
        print(Fore.RED + f"Unexpected error launching admin process: {e}" + Fore.WHITE)
        return False

def check_rootfs_script(fetch_script=False):
    dll_file_path = pathlib.Path(__file__).parent.joinpath("dll_collector.bat")
    if not dll_file_path.exists() or os.path.getsize(str(dll_file_path.resolve())) == 0: 
        print(Fore.RED + "Main dll collector script was not found" + Fore.WHITE)
        if not fetch_script:
            print(Fore.RED + "Not Fetching the script... " + Fore.WHITE)
            return False
        link = "https://raw.githubusercontent.com/qilingframework/qiling/refs/heads/master/examples/scripts/dllscollector.bat"
        get_request = requests.get(link)
        if not get_request.status_code == 200:
            print(Fore.RED + "Failed to recover the script from github..." + Fore.WHITE)
            return False
        response_text = get_request.text
        if not response_text:
            print(Fore.RED  + "Get Response Text is Empty" + Fore.WHITE)
            return False 
        print(Fore.GREEN + "Script has been recovered succesfully.." + Fore.WHITE)
        with open(pathlib.Path(__file__).parent.joinpath("dll_collector.bat"),"w") as file:
            file.write(response_text.strip())
        print(Fore.CYAN + "Script has been succesfully Recovered... " + Fore.WHITE)
        return True
    print(Fore.GREEN  + "Main Script Has been found Successfully" + Fore.WHITE)
    return True

def recover_host_information():
    filename = pathlib.Path(__file__).parent.joinpath("vms_info.json")
    if not os.path.exists(str(filename.reslove())): 
        print(Fore.CYAN + "Required file vms_info.json was not found" + Fore.WHITE)
        return False
    print(Fore.GREEN + "Required File was found" + Fore.WHITE)
    return True

def check_if_rootfs_generated(generate=True):
    repo_name = pathlib.Path(__file__).parent.joinpath("examples")
    if not os.path.exists(str(repo_name.resolve())):
        print(Fore.RED + "[-] Failed to find the required rootfs" + Fore.WHITE)
        if not generate:
            print(Fore.RED + "[-] Aborting Generation..." + Fore.WHITE)
            return False
        if not check_rootfs_script():
            print(Fore.RED + "Something went wrong with dll script its missing" + Fore.WHITE)
            return False
        if not repo_name.exists():
            print(Fore.RED + "[-] rootfs is missing" + Fore.WHITE)
            if not generate:
                print(Fore.RED + "Skipping Generation..." + Fore.WHITE)
                return False
            else:

                os.chdir(pathlib.Path.cwd())
                print(Fore.CYAN + "Generating ROOTFS Directory..." + Fore.WHITE)
                batch_file_path = pathlib.Path(__file__).parent.joinpath("dll_collector.bat").resolve()
                run_as_admin(str(batch_file_path))
                if repo_name.exists():
                    print(Fore.CYAN + "Generation has been succesfull" + Fore.WHITE)
                    check_if_rootfs_generated(False)
                
    print(Fore.CYAN + "Checking if the Required DLLS Has been found" + Fore.WHITE)
    list_of_dlls = list(repo_name.rglob("*.dll"))
    if not list_of_dlls:
        print(Fore.RED + "No System DLLS been found" + Fore.WHITE)
        return False
    print(Fore.CYAN + "[+] Printing Found DLLS" + Fore.WHITE)
    for count,i in enumerate(list_of_dlls):
        print(Fore.CYAN + "[+][DLL {}] {}".format(count,i))

def create_service_file_directory():
    

def create_systemd_service():
    service_path = " ~/.config/systemd/user/qilin-service/"
    systemd_direcotry = pathlib.Path(__file__).parent.joinpath("systemd")
    if not systemd_direcotry.exists():
        print(Fore.CYAN + "Creating SystemD Directory" + Fore.WHITE)
        os.mkdir(str(systemd_direcotry).resolve())
    system_d_file

#check_if_rootfs_generated(generate=False)
#check_rootfs_script(fetch_script=True)