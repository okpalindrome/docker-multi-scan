# Docker-multi-scan

A script to automate docker image vulnerability scanning using open-source tools like `grype`, `trivy` and `docker-scout`. Filters the result to get the unique CVEs/git-vul-ids and store it `.xlsx` file format.

#### Execution Process
1. Get the image details from a input file
2. Pull the image locally if it does not exist
3. Scan using open-source tools and get json files for each
4. Delete pulled image to save the system storage
5. Repeats the process untill all images from the input file is completed
6. Parse the json output files from each tool
7. Filter the unique result with details like CVE, Severity, Package, Installed Version, Fixed Versions and Source. 
8. Keeps track of failed scans or command errors during the process inside `Failed_cases.txt` file (only if failed).


## Pre-requisites
- Python3 and run `pip install xlsxwriter`
- Start Docker (Desktop-GUI or deamon)
- Login to the private registry where the images are hosted. Using `docker login <registry-url>`
- `grype`, `trivy` and `docker-scout` (logged-in using above command) - should be accessible.
- Update respective tools DBs -
  - `grype db update`
  - `trivy` auto db update on the first scan.
  - `docker-scout` real time comparison with multiple sources.


## Run
```python docker-multi-scan.py --help
usage: docker-multi-scan.py [-h] --file FILE --output OUTPUT

Docker image scan and result filtration

options:
  -h, --help            show this help message and exit
  --file FILE, -f FILE  Input file path containing the list of docker images
  --output OUTPUT, -o OUTPUT
                        Output directory path to save json file and excel file
```
