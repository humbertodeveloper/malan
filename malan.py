import hashlib
import subprocess
import vt
import argparse


class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'

def analyze(malware, api_key):
    with open(malware, 'rb') as mal:
        hash_md5 = hashlib.md5(mal.read()).hexdigest()
        hash_sha256 = hashlib.sha256(mal.read()).hexdigest()

        print(f"{Colors.PURPLE}Malware Analyzer - V. 1.0{Colors.ENDC}")
        print(f"{Colors.PURPLE}by Humberto Aquino (https://github.com/humbertodeveloper){Colors.ENDC}")

        print(f"\n{Colors.GREEN}File to analyze: {malware}{Colors.ENDC}\n")

        print(f"{Colors.PURPLE}============ CHECKING MD5/SHA256 HASH{Colors.ENDC}\n")
        print(f"{Colors.BLUE}MD5: {hash_md5}{Colors.ENDC}")
        print(f"{Colors.BLUE}SHA256: {hash_sha256}{Colors.ENDC}\n")

        print(f"{Colors.PURPLE}============ SENDING MD5 INTO VIRUSTOTAL{Colors.ENDC}\n")

        client = vt.Client(api_key)
        file = client.get_object(f"/files/{hash_md5}")

        print(f"{Colors.BLUE}VirusTotal ID: {file.id}{Colors.ENDC}")

        print(f"{Colors.RED}\nMarked as malicious file: ")
        for sec_vendor_key, sec_vendor_items in file.last_analysis_results.items():
            if sec_vendor_items['category'] == "malicious":
                print(f"{sec_vendor_items['engine_name']}: {sec_vendor_items['result']}")
        print(f"{Colors.ENDC}")

        print(f"{Colors.BLUE}DLL API Import List and Functions:\n")
        for pe_info_keys, pe_info_items in file.pe_info.items():
            if pe_info_keys == "import_list":
                for dll in pe_info_items:
                    print(f"- DLL: {dll['library_name']}")
                    for function in dll['imported_functions']:
                        print(f"-- {function}")
                    print("")
        print(f"{Colors.ENDC}")

        print(f"{Colors.BLUE}Signature Info:\n")
        for sig_keys, sig_items in file.signature_info.items():
            if type(sig_items) == str:
                print(f"- {sig_keys}: {sig_items}")
            else:
                print(f"- Certificate: {sig_keys}")
                for cert_info in sig_items:
                    print(f"-- {cert_info['name']}")
        print(f"{Colors.ENDC}")
        client.close()
        print(f"{Colors.PURPLE}============ ANALYZING STATIC DATA (USING CAPA){Colors.ENDC}\n")
        program = "capa"
        args = [malware, "-r", "capa_rules", "-s", "capa_sigs", "-j", "-q"]
        process = subprocess.Popen([program] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate()
        print(output)




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{Colors.PURPLE}Malware Analyzer 1.0 by Humberto Aquino "
                                                 f"(https://github.com/humbertodeveloper){Colors.ENDC}")
    parser.add_argument("file_path", help="Path to the file you want to scan")
    parser.add_argument("api_key", help="VirusTotal API-KEY")
    args = parser.parse_args()
    file_path = args.file_path
    api_key = args.api_key
    analyze(file_path, api_key)