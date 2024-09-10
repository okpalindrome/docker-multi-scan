import json
import xlsxwriter
import re
import os
import argparse
import sys
import subprocess
import shutil
import threading
import time

# List of image names for result filtration
unique_images = set()

# List to store the extracted data
extracted_data = []

# Set to keep track of unique CVEs that have already been processed
processed_cves = set()

# to save images which did not go through the complete scan
images_failed_to_scan = ""

def fetch_grype(filename):
    # Load the JSON data
    with open(filename, 'r', encoding='utf-8') as file:
        data = json.load(file)

    for match in data.get('matches', []):
        vulnerability = match.get('vulnerability', {})
        cve1 = vulnerability.get('id', 'N/A')  # Default to 'N/A' if 'id' is not found
        severity = vulnerability.get('severity', 'N/A')
        # description = vulnerability.get('description', 'N/A')
        fix_versions = vulnerability.get('fix', {}).get('versions', [])
        
        final_cve = cve1

        related_vulnerabilities = match.get('relatedVulnerabilities', [])

        # if the array is not empty
        if related_vulnerabilities:
            related_vulnerabilities_cve2 = [rv.get('id', []) for rv in related_vulnerabilities]
            if related_vulnerabilities_cve2:
                final_cve = related_vulnerabilities_cve2[0] if related_vulnerabilities_cve2[0].startswith("CVE") else cve1

            # per my research if you open GitHub vul ID, you will find the CVE ID same as related_vulnerabilities parameter.
            # for automation, if CVE is not found in related_vulnerabilities ID parameter, it will take the GIT VUL ID 

        if final_cve in processed_cves:
                continue
        

        processed_cves.add(final_cve)
        artifacts = match.get('artifact', {})
        package_name = artifacts.get('name','N/A')
        installed_version = artifacts.get('version', 'N/A')
        
        # Creating a dictionary for the current match
        match_data = {
            'severity': severity.upper(),
            # 'description': description,
            'fixed_versions': ', '.join(fix_versions),  # Convert list to comma-separated string
            'CVE': final_cve,
            'Package': package_name,
            'installed_version': installed_version,
            'source': "Grype"
        }
        
        # Adding the dictionary to the list
        extracted_data.append(match_data)


def fetch_trivy(filename):
    # Load the JSON data
    with open(filename, 'r', encoding='utf-8') as file:
        data = json.load(file)

    for result in data.get('Results', []):
        vulnerabilities = result.get('Vulnerabilities', [])

        for vuls in vulnerabilities:
            VulnerabilityID = vuls.get("VulnerabilityID", 'N/A')

            # there are no multiple sources to compare the ID either its CVE or GitHub vul ID (like from grype).
            if VulnerabilityID in processed_cves:
                continue
            
            processed_cves.add(VulnerabilityID)
            
            PkgName = vuls.get("PkgName", 'N/A')
            InstalledVersion = vuls.get("InstalledVersion", 'N/A')
            FixedVersion = vuls.get("FixedVersion", 'N/A')

            # if the source is Debian Security Tracker, the severity might not be provided.
            Severity = vuls.get("Severity",'N/A')

            # Creating a dictionary for the current match
            findings = {
                'severity': Severity.upper(),
                # 'description': description,
                'fixed_versions': FixedVersion,
                'CVE': VulnerabilityID,
                'Package': PkgName,
                'installed_version': InstalledVersion,
                'source': "Trivy"
            }
        
            # Adding the dictionary to the list
            extracted_data.append(findings)


def fetch_docker_scout(filename):
    # Load the JSON data
    with open(filename, 'r', encoding='utf-8') as file:
        data = json.load(file)

    for scanners in data.get('runs', []):
        vuls = scanners.get('results', [])

        for vul in vuls:
            cve = vul.get("ruleId", 'N/A')
            
            if cve in processed_cves:
                continue

            processed_cves.add(cve)
            info = vul.get("message", {}).get("text", 'N/A')

            # Extracting values using regular expressions
            severity = re.search(r'Severity\s*:\s*(\w+)', info) # sometimes, the source does not provide the severity (UNSPECIFIED).
            package = re.search(r'Package\s*:\s*([\S]+)', info)
            fixed_version = re.search(r'Fixed version\s*:\s*([\S]+)', info)

            # Assigning the extracted values to variables
            severity = severity.group(1) if severity else 'N/A'
            package = package.group(1) if package else 'N/A'
            fixed_version = fixed_version.group(1) if fixed_version else 'N/A'  

            # Creating a dictionary for the current match
            match_data = {
                'severity': severity.upper(),
                # 'description': description,
                'fixed_versions': fixed_version,
                'CVE': cve,
                'Package': package,
                'installed_version': package,
                'source': "Docker-scout"
            }
            
            # Adding the dictionary to the list
            extracted_data.append(match_data)


def create_report(filename, result_dir):
    # Create an Excel file and add a worksheet
    full_path = os.path.join(result_dir, f'{filename}.xlsx')

    workbook = xlsxwriter.Workbook(full_path)
    worksheet = workbook.add_worksheet()

    # Write the headers
    headers = ['CVE','Severity', 'Package', 'Installed Version', 'Fixed Versions', 'Source']
    for col_num, header in enumerate(headers):
        worksheet.write(0, col_num, header)

    # Write the data
    for row_num, match_data in enumerate(extracted_data, start=1):
        worksheet.write(row_num, 0, match_data['CVE'])
        worksheet.write(row_num, 1, match_data['severity'])
        # worksheet.write(row_num, 2, match_data['description']) add the header incase required.
        worksheet.write(row_num, 2, match_data['Package'])
        worksheet.write(row_num, 3, match_data['installed_version'])
        worksheet.write(row_num, 4, match_data['fixed_versions'])
        worksheet.write(row_num, 5, match_data['source'])

    # Close the workbook
    workbook.close()
    reset_globals()
    # print(f"Data has been written to {filename}.xlsx")


def reset_globals():
    global extracted_data
    global processed_cves
    
    extracted_data = []
    processed_cves = set()


def initiate_filtration(json_dir, result_dir):

    for element in unique_images:
        print(f"Filtering results for - {element}")
        full_path = os.path.join(json_dir, "grype_" + element)
        if os.path.isfile(full_path):
            fetch_grype(full_path)
        
        full_path = os.path.join(json_dir, "trivy_" + element)
        if os.path.isfile(full_path):
            fetch_trivy(full_path)

        full_path = os.path.join(json_dir, "docker_scout_"+ element)
        if os.path.isfile(full_path):
            fetch_docker_scout(full_path)

        create_report(element, result_dir)

def read_image_list(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def execute_command(command, message, source_image):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        stderr_str = e.stderr.decode('utf-8') if e.stderr else ""
        if "Image is up to date" in stderr_str:
            print(f"{source_image} already exists locally, skipping pull.")
            return True
        else:
            print(f"{message} on image: {image}")

        with open(images_failed_to_scan, 'a') as file:
            file.write(message + " - " + source_image + "\n")
            print(e)
        return False

def execute_scan(inputfile, outputfile):
    images = read_image_list(inputfile)
    total_images = len(images)
    print(f"[INFO]  Total number of images to scan: {total_images}")
    processed_images = 0

    for image in images:
        json_file = image.replace('/', '_').replace(':', '_') + '.json'

        docker_pull_command = f"docker pull {image}"

        grype_command = fr"grype {image} -o json > {outputfile}\json-files\grype_{json_file}" # Also kubescape tool 
         
        trivy_command = fr"trivy image {image} --format json > {outputfile}\json-files\trivy_{json_file}" 
        
        docker_scout_command = fr"docker-scout cves image://{image} --format sarif -o {outputfile}\json-files\docker_scout_{json_file}"

        docker_remove_command = f"docker rmi {image}"
        # delete_tar_command = f"del {tar_file_path}"

        print(f"[INFO]  Pulling, scanning and filtering results - {image}")

        # Execute the Docker pull command
        if not execute_command(docker_pull_command, "Unable to pull",image):
            print(f"Failed to pull Docker image: {image}")
            processed_images += 1
            continue  

        start_time = time.time()
        thread1 = threading.Thread(target=execute_command, args=(grype_command,"Grype failed", image,))
        thread2 = threading.Thread(target=execute_command, args=(trivy_command,"Trivy failed", image,))
        thread3 = threading.Thread(target=execute_command, args=(docker_scout_command, "Docker-scout failed", image,))

        thread1.start()
        thread2.start()
        thread3.start()

        thread1.join()
        thread2.join()
        thread3.join()
        
        # Remove the Docker image
        if not execute_command(docker_remove_command, "Unable to remove image", image):
            print(f"Failed to remove Docker image: {image}")  

        end_time = time.time()
        duration = end_time - start_time

        unique_images.add(json_file)

        processed_images += 1
        print(f"[INFO]  Successfully processed and cleaned up image: {image} in {duration}.")
        print(f"[INFO]  Progress: {processed_images}/{total_images} images completed\n\n")

def prerequisites_checks():
    print("[CHECK]  Checking for pre-requisites ...")
    try:
        docker_daemon = subprocess.run(['docker', 'info'], capture_output=True, text=True, check=True)
        print("[CHECK]  Docker Daemon Running ...")
        
        grype = subprocess.run(['grype', '--help'], capture_output=True, text=True, check=True)
        print ("[CHECK]  Grype tool is accessible ...")

        trivy = subprocess.run(['trivy', '--help'], capture_output=True, text=True, check=True) 
        print ("[CHECK]  Trivy tool is accessible ...")

        docker_scout_cli = subprocess.run(['docker-scout', '--help'], capture_output=True, text=True, check=True)
        print ("[CHECK]  Docker-Scout tool is accessible ...")

    except subprocess.CalledProcessError as e:
        print("[ERROR]  Docker daemon is not running.")
        sys.exit(1)
    except FileNotFoundError:
        print("A required tool was not found.")
        print(f"Error: {e}")
        sys.exit(1)



def main():

    global images_failed_to_scan

    parser = argparse.ArgumentParser(description="Docker image scan and result filtration")
    parser.add_argument("--file", "-f", required=True, type=str, help="Input file path containing the list of docker images")
    parser.add_argument("--output", "-o", required=True, type=str, help="Output directory path to save json file and excel file")
    args = parser.parse_args()

    # Check if the input file and directory exists. Later, create directories - json-files and results
    args.file = os.path.normpath(args.file)
    args.output = os.path.normpath(args.output)

    if os.path.isfile(args.file) and os.path.isdir(args.output):
        json_dir = os.path.join(args.output, "json-files")
        result_dir = os.path.join(args.output, "results")
        images_failed_to_scan = os.path.join(args.output, "Failed_cases.txt")
        
        try:
            if os.path.isdir(json_dir):
                shutil.rmtree(json_dir)

            if os.path.isdir(result_dir):
                shutil.rmtree(result_dir)

            # re-creating directories
            os.makedirs(json_dir)
            os.makedirs(result_dir)

            if os.path.isfile(images_failed_to_scan):
                os.remove(images_failed_to_scan)

            # re-create the file
            with open(images_failed_to_scan, 'w') as temp:
                pass

        except OSError as e:
            print(f"An error occurred while creating directories and temp file : {e}")
            sys.exit(1)
    else:
        if not os.path.isfile(args.file):
            print(f"The input file path does not exist: {args.file}")
        if not os.path.isdir(args.output):
            print(f"The output directory does not exist: {args.output}")
        sys.exit(1)

    prerequisites_checks()
    
    print("\n\n[INFO]  Docker Image Scanning Phase ...")
    execute_scan(args.file, args.output)
    
    print("\n[INFO]  Result Filtration Phase")
    initiate_filtration(json_dir, result_dir)

    if os.path.getsize(images_failed_to_scan) == 0:
        os.remove(images_failed_to_scan)
    else:
        print(f"[INFO]  Few things did not work, checkout {images_failed_to_scan} for more details")



if __name__ == "__main__":
    main()
