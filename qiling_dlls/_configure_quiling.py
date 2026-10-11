import paramiko
import json
import requests
import os
import sys
import subprocess
import pathlib
import tarfile
from jinja2 import Environment, FileSystemLoader
from colorama import Fore,Back,init

init()

TEMPLATES_DIR = pathlib.Path(__file__).parent.joinpath("templates")
STAGING_DIR = pathlib.Path(__file__).parent.parent.joinpath(
    "config", "systemd", "qilin-service")
SERVICE_UNIT = "qilin-service.service"
ROOTFS_SRC = pathlib.Path(__file__).parent.joinpath("examples").joinpath("rootfs")
ROOTFS_TAR = "rootfs.tar.gz"

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
    filename = pathlib.Path(__file__).parent.joinpath("vm_info.json")
    if not os.path.exists(str(filename.resolve())): 
        print(Fore.CYAN + "Required file vms_info.json was not found" + Fore.WHITE)
        return None
    print(Fore.GREEN + "Required File was found" + Fore.WHITE)
    json_content = {}
    with open(str(filename.resolve())) as file:
        try:
            json_content = json.loads(file.read())       
        except Exception as e:
            print(Fore.RED + "Failed to read the requied json file : {}".format(e) + Fore.WHITE)
    print(Fore.CYAN + "Recovered the hosts informration correctly" + Fore.WHITE)
    return json_content


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
    dll_counts =  len(list_of_dlls)
    for count,i in enumerate(list_of_dlls):
        print(Fore.CYAN + "[+][DLL {}] {}".format(count,i))
    print(Fore.CYAN + "Recovered N°{}".format(dll_counts) + Fore.WHITE)

def check_ssh_connectivity_normal_user(json_info=None) -> paramiko.SSHClient:
    if json_info is None:
        json_info = recover_host_information()
    if not json_info:
        print(Fore.RED + "Failed to recover the required information"+ Fore.WHITE)
        return None
    VM_IP = json_info.get("VM_IP")
    VM_PORT = json_info.get("VM_PORT", 22)
    VM_USER = json_info.get("VM_HOST")
    VM_PASSWORD = json_info.get("VM_PASSWORD")

    print(Fore.BLUE + "Connecting to {}@{}:{}".format(VM_USER, VM_IP, VM_PORT) + Fore.WHITE)
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.load_system_host_keys()
        project_keys = pathlib.Path(__file__).parent.joinpath("known_hosts.ssh")
        if project_keys.exists():
            ssh_client.load_host_keys(str(project_keys.resolve()))
        ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
        ssh_client.connect(hostname=VM_IP,username=VM_USER,port=VM_PORT,password=VM_PASSWORD, timeout=10)
        print(Fore.GREEN + "Connected to host correctly..." + Fore.WHITE)
        return ssh_client
    except Exception as e:
        print(Fore.RED + "Something went wrong while testing paramiko connection : {}".format(e) + Fore.WHITE)
        return None


def check_if_required_tools_installed():
    apt_required_packages = "python3"
def create_service_file_directory():
    pass

def transfer_rootfs(ssh_client, app_dir):
    """gzip the local rootfs, upload it, extract on the VM, delete the tar."""
    if not ROOTFS_SRC.is_dir():
        print(Fore.RED + "rootfs not found at {}".format(ROOTFS_SRC) + Fore.WHITE)
        return False
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    local_tar = STAGING_DIR.joinpath(ROOTFS_TAR)
    try:
        file_count = sum(1 for _ in ROOTFS_SRC.rglob("*") if _.is_file())
        print(Fore.CYAN + "Compressing rootfs ({} files, gzip/zlib)..."
              .format(file_count) + Fore.WHITE)
        with tarfile.open(str(local_tar), "w:gz", compresslevel=6) as tar:
            tar.add(str(ROOTFS_SRC), arcname="rootfs")
        total = local_tar.stat().st_size
        print(Fore.CYAN + "Archive {:.1f} MB - uploading...".format(
            total / 1e6) + Fore.WHITE)

        last_decile = [0]

        def _progress(sent, _total):
            decile = sent * 10 // _total
            if decile > last_decile[0]:
                last_decile[0] = decile
                print(Fore.CYAN + "  upload {}0%".format(decile) + Fore.WHITE)

        sftp = ssh_client.open_sftp()
        sftp.put(str(local_tar), "{}/{}".format(app_dir, ROOTFS_TAR),
                 callback=_progress)
        sftp.close()
        _, out, err = ssh_client.exec_command(
            "tar -xzf '{app}/{tar}' -C '{app}' && rm -f '{app}/{tar}'"
            .format(app=app_dir, tar=ROOTFS_TAR))
        status = out.channel.recv_exit_status()
        if status != 0:
            detail = err.read().decode(errors="replace").strip()
            raise RuntimeError("extract failed ({}) : {}".format(status, detail))
        print(Fore.GREEN + "rootfs extracted to {}/rootfs and tar deleted"
              .format(app_dir) + Fore.WHITE)
        return True
    except Exception as e:
        print(Fore.RED + "rootfs transfer failed: {}".format(e) + Fore.WHITE)
        return False
    finally:
        local_tar.unlink(missing_ok=True)

def create_systemd_service(ssh_client, json_info=None, with_rootfs=True):
    if not ssh_client:
        print(Fore.RED + "No Valid Connection has been found" + Fore.WHITE)
        return False
    if json_info is None:
        json_info = recover_host_information() or {}

    # Paths must match templates/qilin-service.service.j2 defaults:
    #   payload : /home/<user>/.config/systemd/qilin-service/
    #   unit    : /home/<user>/.config/systemd/user/qilin-service.service
    service_user = str(json_info.get("VM_HOST") or "qilin").strip() or "qilin"
    home = "/home/{}".format(service_user)
    app_dir = "{}/.config/systemd/qilin-service".format(home)
    unit_remote = "{}/.config/systemd/user/{}".format(home, SERVICE_UNIT)

    template_file = TEMPLATES_DIR.joinpath(SERVICE_UNIT + ".j2")
    if not template_file.exists():
        print(Fore.RED + "Service template not found: {}".format(template_file) + Fore.WHITE)
        return False

    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)),
                      keep_trailing_newline=True)
    rendered = env.get_template(template_file.name).render(
        service_user=service_user, app_dir=app_dir)

    try:
        STAGING_DIR.mkdir(parents=True, exist_ok=True)
        staged_unit = STAGING_DIR.joinpath(SERVICE_UNIT)
        with open(str(staged_unit), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(rendered)
        print(Fore.CYAN + "Rendered unit -> {}".format(staged_unit) + Fore.WHITE)
    except OSError as e:
        print(Fore.RED + "Failed to write the staged unit: {}".format(e) + Fore.WHITE)
        return False

    script_src = pathlib.Path(__file__).parent.joinpath("_qiling_script.py")
    try:
        _, out, err = ssh_client.exec_command(
            "mkdir -p '{}/.config/systemd/user' '{}'".format(home, app_dir))
        if out.channel.recv_exit_status() != 0:
            detail = err.read().decode(errors="replace").strip()
            raise RuntimeError("mkdir failed: {}".format(detail))
        sftp = ssh_client.open_sftp()
        sftp.put(str(staged_unit), unit_remote)
        if script_src.exists():
            sftp.put(str(script_src), app_dir + "/qilin-script.py")
        sftp.close()
        if with_rootfs and not transfer_rootfs(ssh_client, app_dir):
            raise RuntimeError("rootfs transfer failed - unit and script are "
                               "installed but the service cannot run yet")
        _, out, err = ssh_client.exec_command(
            "XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user daemon-reload")
        status = out.channel.recv_exit_status()
        if status != 0:
            detail = err.read().decode(errors="replace").strip()
            print(Fore.YELLOW + "daemon-reload returned {} ({}); unit file "
                  "is installed anyway".format(status, detail) + Fore.WHITE)
    except Exception as e:
        print(Fore.RED + "Failed to install the systemd unit: {}".format(e) + Fore.WHITE)
        return False

    print(Fore.GREEN + "Unit installed at {}".format(unit_remote) + Fore.WHITE)
    if script_src.exists():
        print(Fore.GREEN + "Entry point installed at {}/qilin-script.py"
              .format(app_dir) + Fore.WHITE)
    else:
        print(Fore.RED + "Entry point MISSING locally ({}) - copy it as "
              "{}/qilin-script.py".format(script_src, app_dir) + Fore.WHITE)
    if not with_rootfs:
        print(Fore.CYAN + "Rootfs skipped - copy examples/rootfs manually to "
              "{}/rootfs".format(app_dir) + Fore.WHITE)
    print(Fore.CYAN + "enable with: systemctl --user enable "
          "qilin-service.service (oneshot - start per sample with "
          "script_args holding the sample path)" + Fore.WHITE)
    return True



def test_connectivity_to_service():
    pass
def full_pipeline():
    json_info = recover_host_information()
    if not json_info:
        print(Fore.RED + "Failed to recover host information, aborting" + Fore.WHITE)
        return False
    test_ssh = check_ssh_connectivity_normal_user(json_info)
    if not test_ssh:
        print(Fore.RED + "Failed to connect to the required user aborting" + Fore.WHITE)
        return False
    try:
        return create_systemd_service(test_ssh, json_info)
    finally:
        print(Fore.GREEN + "Closing SSH Connection..." + Fore.WHITE)
        test_ssh.close()

full_pipeline

#check_if_rootfs_generated(generate=False)
#check_rootfs_script(fetch_script=True)