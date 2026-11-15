from bs4 import BeautifulSoup as soup
import os
from colorama import Fore,Back,init
import uuid
import subprocess
import sys
import pathlib
import requests
import shutil


init()
UNPROTECT_IT_URL =  "https://unprotect.it/detection-rules/"
print(Fore.CYAN + "[*] Checking if the required files are found" + Fore.WHITE)
PATH_FOR_SRC_FILES = pathlib.Path().cwd().joinpath("html_src").resolve()
RESULTS_DIR = pathlib.Path().cwd().joinpath("extracted_rules")

def scrape_website_via_httrack() -> bool:
    original_path = str(pathlib.Path().cwd().resolve())
    print(Fore.CYAN + "[*] Extracting unprotect it detection rules via httrack" + Fore.WHITE)
    httrack_executable = shutil.which("httrack")
    if not httrack_executable:
        print(Fore.RED + "[-] Failed to run the httrack executbale something went wrong with the extraction pipeline" + Fore.WHITE)
        return False
    if not PATH_FOR_SRC_FILES.exists(): 
        print(Fore.CYAN + "[+] Creating results directory...")
        os.mkdir(str(PATH_FOR_SRC_FILES))
    os.chdir(str(PATH_FOR_SRC_FILES))
    httrack_command = ["httrack",UNPROTECT_IT_URL]
    execute_command = subprocess.run(httrack_command,capture_output=True,text=True)
    if execute_command.returncode != 0:
        print(Fore.RED + "[-] Failed to execute the given command reason : {}".format(execute_command.stderr) + Fore.WHITE)
        return False
    os.chdir(original_path) 
    print(Fore.GREEN + "[+] Checking if website is extracted Correctly" + Fore.WHITE)
    ### dont change it to True or it will introduce a recursion error and will stack overflow you don't want that shit trust me :D
    if not check_root_files(False):
        print(Fore.RED + "[-] Failed to extract the files correctly" + Fore.WHITE)
        return False
    print(Fore.GREEN + "[+] Correctly Extracted the required files" + Fore.WHITE)
    return True

def check_root_files(extract_files=True):
    if not PATH_FOR_SRC_FILES.exists():
        if not extract_files:
            print(Fore.RED + "[-] Failed to extract the required files" + Fore.WHITE)
            return False
        else:
            if not scrape_website_via_httrack():
                print(Fore.RED + "[-] Failed to extract the required files" + Fore.WHITE)
                return False
    print(Fore.CYAN + "[*] Checking if there any html files to scrape..." + Fore.WHITE)
    html_files_found = False
    index_file = False
    for i in os.scandir(str(PATH_FOR_SRC_FILES)):
        if i.is_file():
            if str(i.name) == "index.html":
                print(Fore.GREEN + "[*] Index file has been found" + Fore.WHITE)
                index_file = True
    print(Fore.CYAN + "[*] Checking the available html files" + Fore.WHITE)
    
    directory_path = str()
    for i in os.scandir(str(PATH_FOR_SRC_FILES.resolve())):
        if i.is_dir():
            print(Fore.GREEN + "[+] Directory has been found..." + Fore.WHITE)
            directory_path = str(i.path)
    print(Fore.CYAN + "[+] Checking if the directory contains any html files" + Fore.WHITE)
    li = pathlib.Path(directory_path).rglob("*.html")
    if li:
        html_files_found = True 
        print(Fore.CYAN + "[+] HTML files has been found.." + Fore.WHITE)

    if not (html_files_found and index_file):
        print(Fore.RED + "[-] Failed to find the required files to extract the data" + Fore.WHITE)
        if not extract_files:
            print(Fore.RED + "[-] Failed to extract the required files extract_files parameter is disabled" + Fore.WHITE)
            return False
        else: 
            if not scrape_website_via_httrack():
                print(Fore.RED + "[-] Failed to extract the required files" + Fore.WHITE)
                return False
        print(Fore.GREEN  + "[+] Extracted website is ready to be used" + Fore.WHITE)
    return True


def resolve_extension(extension) -> dict:
    if not extension:
        print(Fore.GREEN + "[+] Failed to resolve extension" + Fore.WHITE)
        return None
    if not extension in ["capa","yara","sigma"]:
        print(Fore.RED + "[-] Invalid file type given" + Fore.WHITE)
        return None
    if extension == "capa":
        print(Fore.CYAN  + "[+] CAPA extension found" + Fore.WHITE)
        return {"directory":"capa","extension":".capa"}
    if extension == "sigma":
        print(Fore.CYAN + "[+] SIGMA extension found" + Fore.WHITE)
        return {"directory":"sigma","extension":".yaml"}
    if extension == "yara":
        print(Fore.CYAN + "[+] YARA rule found" + Fore.WHITE)
        return {"directory":"yara","extension":".yar"}

def read_html(extract_files=True)  -> bool: 
    if  not check_root_files(extract_files):
        print(Fore.RED + "[-] Given Files are not ready to be used" + Fore.WHITE)
        return False

    index_path = PATH_FOR_SRC_FILES.joinpath("index.html")
    other_html_files = list(PATH_FOR_SRC_FILES.joinpath("unprotect.it").rglob("*.html"))
    other_html_files.append(index_path)
    list_of_elements = []
    for i in other_html_files:
        path = str(i.resolve()) 
        with open(path) as file:
            parser = soup(file,'html.parser')
            tr_lines = parser.find_all("table")[0]
            for i in tr_lines.find_all("tr"):
                col = i.find_all("td")
                if len(col) > 3:
                    targeted_col = col[0]
                    url = targeted_col.find("a").get("href")
                    rule_name = targeted_col.get_text()
                    file_type = col[1].find("a").get_text()
                    row_type = dict()
                    row_type.setdefault("rule_name",rule_name)
                    row_type.setdefault("file_type",file_type.lower())
                    row_type.setdefault("url",url)
                    list_of_elements.append(row_type)

    if not list_of_elements:
        print(Fore.RED  + "[-] Failed to extract any endpoints" + Fore.WHITE)
        return False
    
    print(Fore.GREEN  + "[+] Found the required elements.." + Fore.WHITE)
    list_of_dirs = ["capa","yara","sigma"]
    if not RESULTS_DIR.exists(): 
        os.mkdir(str(RESULTS_DIR.resolve()))
   
    for i in list_of_dirs:
       dir_path = RESULTS_DIR.joinpath(i)
       if not dir_path.exists():
           os.mkdir(str(dir_path))

    for i in list_of_elements:
        rule_name = i.get('rule_name')
        if rule_name.find(' ') != -1:
            rule_name = rule_name.replace(' ',"_")
        if rule_name.find('\'') != -1:
            rule_name = rule_name.replace('\'',"_")
        rule_name = rule_name.strip('\n')
        url = i.get("url")
        if not url:
            print(Fore.YELLOW + "[*] Continuing to the next endpoint url is missing" + Fore.WHITE)
            continue
        url = url + "raw/"
        print(Fore.BLUE + "[+] Sending Get Request to endpoint: {}".format(url) + Fore.WHITE)
        get_request = requests.get(url)
        if not get_request.status_code == 200:
            print(Fore.YELLOW + "[*] Failed to extract the content of the rule file : {} ".format(i.get("rule_name")) + Fore.WHITE) 
            continue
        content = get_request.text
        file_type = i.get("file_type")
        extension = resolve_extension(file_type.lower())
        if not extension:
            print(Fore.YELLOW + "[*] Failed to resolve extension" + Fore.WHITE)
            continue
        full_file_name = rule_name +  extension.get("extension",".txt")
        results_path = RESULTS_DIR.joinpath(extension.get("directory")).joinpath(full_file_name).resolve()
        try:
            with open(str(results_path),"w+",encoding='utf-8') as file:
                file.write(content)
            print(Fore.GREEN  + "[+] {} has been created successfully".format(i.get('rule_name').strip('\n')) + Fore.WHITE)
        except Exception as e:
            print(Fore.RED + "Failed to save the current rules: {} reason : {}".format(i.get('rule_name').strip('\n'),e) + Fore.WHITE)
            continue
            
    return True


try:
    results = read_html()
    print("Results are found : {}".format(results))
except Exception as  e:
    print(Fore.RED + "Something went wrong with the analysis: {}".format(e) + Fore.WHITE)
    raise
