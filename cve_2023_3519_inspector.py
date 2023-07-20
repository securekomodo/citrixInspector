#!/usr/bin/env python3
# coding=utf-8
#
# AUTHOR
# Bryan Smith (@securekomodo)


import argparse
import requests
from bs4 import BeautifulSoup
import re
import logging
import warnings
import sys
import subprocess
import pkg_resources

# Check if the OpenSSL version is the one required (required if running on OSX)
REQUIRED_VERSION = "1.26.6"
try:
    # Get the current version of urllib3
    current_version = pkg_resources.get_distribution("urllib3").version
except pkg_resources.DistributionNotFound:
    current_version = None

# Check if the urllib3 version is not the one required
if current_version != REQUIRED_VERSION:
    # Install the specific version of urllib3 (OSX Fix)
    subprocess.call([sys.executable, "-m", "pip", "install", f'urllib3=={REQUIRED_VERSION}'])

# Ignore all the SSL/TLS certificate warnings
warnings.filterwarnings('ignore')

# The array of hashes and corresponding versions.
hash_versions = [
    {"vhash": "26df0e65fba681faaeb333058a8b28bf", "version": "12.1-50.28"},
    {"vhash": "d3b5c691a4cfcc6769da8dc4e40f511d", "version": "12.1-50.31"},
    {"vhash": "995a76005c128f4e89474af12ac0de66", "version": "12.1-51.16"},
    {"vhash": "d2bd166fed66cdf035a0778a09fd688c", "version": "12.1-51.19"},
    {"vhash": "86b4b2567b05dff896aae46d6e0765bc", "version": "13.0-36.27"},
    {"vhash": "43a8abf580ea09a5fa8aa1bd579280b9", "version": "13.0-41.20"},
    {"vhash": "7116ed70ec000da9267a019728ed951e", "version": "13.0-41.28"},
    {"vhash": "8c62b39f7068ea2f3d3f7d40860c0cd4", "version": "12.1-55.13"},
    {"vhash": "fedb4ba86b5edcbc86081f2893dc9fdf", "version": "13.0-47.22"},
    {"vhash": "02d30141fd053d5c3448bf04fbedb8d6", "version": "12.1-55.18"},
    {"vhash": "fd96bc8977256003de05ed84270b90bb", "version": "13.0-47.24"},
    {"vhash": "f787f9a8c05a502cd33f363e1e9934aa", "version": "12.1-55.24"},
    {"vhash": "e79f3bbf822c1fede6b5a1a4b6035a41", "version": "13.0-52.24"},
    {"vhash": "f2db014a3eb9790a19dfd71331e7f5d0", "version": "12.1-56.22"},
    {"vhash": "fdf2235967556bad892fbf29ca69eefd", "version": "13.0-58.30"},
    {"vhash": "4ecb5abf6e4b1655c07386a2c958597c", "version": "12.1-57.18"},
    {"vhash": "dcb06155d51a0234e9d127658ef9f21f", "version": "13.0-58.32"},
    {"vhash": "12c4901ecc3677aad06f678be49cb837", "version": "13.0-61.48"},
    {"vhash": "b1b38debf0e55c285c72465da3715034", "version": "12.1-58.15"},
    {"vhash": "06fbfcf525e47b5538f856965154e28c", "version": "13.0-64.35"},
    {"vhash": "7a0c8874e93395c5e4f1ef3e5e600a25", "version": "12.1-59.16"},
    {"vhash": "a8e0eb4a1b3e157e0d3a5e57dc46fd35", "version": "13.0-67.39"},
    {"vhash": "0aef7f8e9ea2b528aa2073f2875a28b8", "version": "12.1-55.190"},
    {"vhash": "e2444db11d0fa5ed738aa568c2630704", "version": "13.0-67.43"},
    {"vhash": "9b545e2e4d153348bce08e3923cdfdc1", "version": "13.0-71.40"},
    {"vhash": "25ad60e92a33cbb5dbd7cd8c8380360d", "version": "13.0-71.44"},
    {"vhash": "0b516b768edfa45775c4be130c4b96b5", "version": "12.1-60.19"},
    {"vhash": "b3deb35b8a990a71acca052fd1e6e6e1", "version": "12.1-55.210"},
    {"vhash": "83e486e7ee7eb07ab88328a51466ac28", "version": "12.1-61.18"},
    {"vhash": "454d4ccdefa1d802a3f0ca474a2edd73", "version": "13.0-76.29"},
    {"vhash": "08ff522057b9422863dbabb104c7cf4b", "version": "12.1-61.19"},
    {"vhash": "648767678188e1567b7d15eee5714220", "version": "13.0-76.31"},
    {"vhash": "ce5da251414abbb1b6aed6d6141ed205", "version": "12.1-61.19"},
    {"vhash": "5e55889d93ff0f13c39bbebb4929a68e", "version": "13.0-79.64"},
    {"vhash": "35389d54edd8a7ef46dadbd00c1bc5ac", "version": "12.1-62.21"},
    {"vhash": "8e4425455b9da15bdcd9d574af653244", "version": "12.1-62.23"},
    {"vhash": "73952bdeead9629442cd391d64c74d93", "version": "13.0-82.41"},
    {"vhash": "25169dea48ef0f939d834468f3c626d2", "version": "13.0-82.42"},
    {"vhash": "efb9d8994f9656e476e80f9b278c5dae", "version": "12.1-62.25"},
    {"vhash": "e1ebdcea7585d24e9f380a1c52a77f5d", "version": "12.1-62.27"},
    {"vhash": "eb3f8a7e3fd3f44b70c121101618b80d", "version": "13.0-82.45"},
    {"vhash": "98a21b87cc25d486eb4189ab52cbc870", "version": "13.1-4.43"},
    {"vhash": "c9e95a96410b8f8d4bde6fa31278900f", "version": "13.0-83.27"},
    {"vhash": "f3d4041188d723fec4547b1942ffea93", "version": "12.1-63.22"},
    {"vhash": "158c7182df4973f1f5346e21e9d97a01", "version": "13.1-4.44"},
    {"vhash": "a66c02f4d04a1bd32bfdcc1655c73466", "version": "13.0-83.29"},
    {"vhash": "5cd6bd7d0aec5dd13a1afb603111733a", "version": "12.1-63.23"},
    {"vhash": "645bded68068748e3314ad3e3ec8eb8f", "version": "13.1-9.60"},
    {"vhash": "5112d5394de0cb5f6d474e032a708907", "version": "13.1-12.50"},
    {"vhash": "3a316d2de5362e9f76280b3157f48d08", "version": "13.0-84.10"},
    {"vhash": "ee44bd3bc047aead57bc000097e3d8aa", "version": "12.1-63.24"},
    {"vhash": "2b46554c087d2d5516559e9b8bc1875d", "version": "13.0-84.11"},
    {"vhash": "cf9d354b261231f6c6121058ba143af7", "version": "13.1-12.51"},
    {"vhash": "c6bcd2f119d83d1de762c8c09b482546", "version": "12.1-64.16"},
    {"vhash": "b3fb0319d5d2dad8c977b9986cc26bd8", "version": "12.1-55.265"},
    {"vhash": "0f3a063431972186f453e07954f34eb8", "version": "13.1-17.42"},
    {"vhash": "e42d7b3cf4a6938aecebdae491ba140c", "version": "13.0-85.15"},
    {"vhash": "2edf0f445b69b2e322e80dbc3f6f711c", "version": "12.1-55.276"},
    {"vhash": "b4ac9c8852a04234f38d73d1d8238d37", "version": "13.1-21.50"},
    {"vhash": "9f73637db0e0f987bf7825486bfb5efe", "version": "12.1-55.278"},
    {"vhash": "c212a67672ef2da5a74ecd4e18c25835", "version": "12.1-64.17"},
    {"vhash": "fbdc5fbaed59f858aad0a870ac4a779c", "version": "12.1-65.15"},
    {"vhash": "1884e7877a13a991b6d3fac01efbaf79", "version": "13.0-85.19"},
    {"vhash": "853edb55246c138c530839e638089036", "version": "13.1-24.38"},
    {"vhash": "7a45138b938a54ab056e0c35cf0ae56c", "version": "13.0-86.17"},
    {"vhash": "4434db1ec24dd90750ea176f8eab213c", "version": "12.1-65.17"},
    {"vhash": "469591a5ef8c69899320a319d5259922", "version": "12.1-55.282"},
    {"vhash": "adc1f7c850ca3016b21776467691a767", "version": "13.1-27.59"},
    {"vhash": "1f63988aa4d3f6d835704be50c56788a", "version": "13.0-87.9"},
    {"vhash": "57d9f58db7576d6a194d7dd10888e35", "version": "13.1-30.52"},
    {"vhash": "7afe87a42140b566a2115d1e232fdc07", "version": "13.1-33.47"},
    {"vhash": "c1b64cea1b80e973580a73b787828daf", "version": "12.1-65.21"},
    {"vhash": "4d817946cef53571bc303373fd6b406b", "version": "12.1-55.289"},
    {"vhash": "aff0ad8c8a961d7b838109a7ee532bcb", "version": "13.1-33.49"},
    {"vhash": "37c10ac513599cf39997d52168432c0e", "version": "13.0-88.12"},
    {"vhash": "27292ddd74e24a311e4269de9ecaa6e7", "version": "13.0-88.13"},
    {"vhash": "5e939302a9d7db7e35e63a39af1c7bec", "version": "13.1-33.51"},
    {"vhash": "6e7b2de88609868eeda0b1baf1d34a7e", "version": "13.0-88.14"},
    {"vhash": "56672635f81a1ce1f34f828fef41d2fa", "version": "13.1-33.52"},
    {"vhash": "9bf6d5d3131495969deba0f850447947", "version": "13.1-33.54"},
    {"vhash": "3bd7940b6425d9d4dba7e8b656d4ba65", "version": "13.0-88.16"},
    {"vhash": "0d656200c32bb47c300b81e599260c42", "version": "13.1-37.38"},
    {"vhash": "953fae977d4baedf39e83c9d1e134ef1", "version": "12.1-55.291"},
    {"vhash": "f063b04477adc652c6dd502ac0c39a75", "version": "12.1-65.25"}
]

def is_site_vulnerable(url):
    print(f"{url} - Checking if vulnerable to CVE-2023-3519")
    try:
        logging.info(f"Making request to {url}")
        response = requests.get(url, verify=False)
    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while trying to connect to {url}. Error: {e}")
        return

    html_content = response.text

    soup = BeautifulSoup(html_content, 'html.parser')

    # Initialize checks
    title_check = False
    comment_check = False
    icon_check = False
    hash_exists = False
    hash_check = False
    identified_version = None

    # Check if the title is "Citrix Gateway"
    if soup.title.string == "Citrix Gateway":
        title_check = True
        logging.info(f"{url} - Title Check Passed")

    # Check for "frame-busting" HTML comment
    if "frame-busting" in html_content:
        comment_check = True
        logging.info(f"{url} - HTML comment check Passed")

    # Check for icon
    icon_check = "/vpn/images/AccessGateway.ico" in html_content or "receiver/images/common/icon_vpn.ico" in html_content
    if icon_check:
        logging.info(f"{url} - Icon check Passed")

    # Check if ANY hash is identified in HTML content - signifies older version as this was fixed in new releases
    pattern = r'v=[a-fA-F0-9]{32}'

    # Search for the pattern in the text
    match = re.search(pattern, html_content)

    # If a match is found
    if match:
        hash_exists = True
        logging.info(f"{url} - Hash found")

        # Check for the presence of identified hashes in the HTML content
        for hash_version in hash_versions:
            if hash_version["vhash"] in html_content:
                hash_check = True
                identified_version = hash_version["version"]
                logging.info(f"{url} - Version check Passed")
                break

    else:
        logging.info(f"{url} - Hash check Not Found")



    # Decision making based on the checks
    if hash_check:
        logging.info(f"{url} - [VULNERABLE] Netscaler / Citrix ADC detected! Identified version: {identified_version}")
        print(f"{url} - [VULNERABLE] Netscaler / Citrix ADC detected! Identified version: {identified_version}")
    elif title_check and comment_check and icon_check and hash_exists:
        logging.info(f"{url} - [VULNERABLE] Netscaler / Citrix ADC detected based off passive fingerprinting.")
        print(f"{url} - [VULNERABLE] Netscaler / Citrix ADC detected based off passive fingerprinting.")
    elif icon_check and not title_check and not comment_check:
        logging.info(f"{url} - Possible Netscaler / Citrix ADC detected")
        print(f"{url} - Possible Netscaler / Citrix ADC detected")
    else:
        logging.info(f"{url} - No Netscaler / Citrix ADC detected")
        print(f"{url} - No Netscaler / Citrix ADC detected")

def process_urls(urls):
    for url in urls:
        is_site_vulnerable(url.strip())

def main():
    # Display the banner
    print("""

    Author: Bryan Smith (@securekomodo)
    ------------------------
    _________ .__  __         .__                              
    \_   ___ \|__|/  |________|__|__  ___                      
    /    \  \/|  \   __\_  __ \  \  \/  /                      
    \     \___|  ||  |  |  | \/  |>    <                       
     \______  /__||__|  |__|  |__/__/\_ \                      
        \/                         \/                      
    .___                                     __                
    |   | ____   ____________   ____   _____/  |_  ___________ 
    |   |/    \ /  ___/\____ \_/ __ \_/ ___\   __\/  _ \_  __ \\
    |   |   |  \\___ \ |  |_> >  ___/\  \___|  | (  <_> )  | \/
    |___|___|  /____  >|   __/ \___  >\___  >__|  \____/|__|   
             \/     \/ |__|        \/     \/                                

       CVE-2023-3519 Inspector
       ------------------------
       """)
    parser = argparse.ArgumentParser(description="Check for vulnerabilities in Citrix Gateway.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help="The URL of the Citrix Gateway to check.")
    group.add_argument('-f', '--file', help="A file containing a list of URLs to check.")
    parser.add_argument('-l', '--log', default='cve_2023_3519_inspector.log', help="Log file to write the output.")
    args = parser.parse_args()

    logging.basicConfig(filename=args.log, filemode='w', format='%(message)s', level=logging.INFO)

    if args.url:
        is_site_vulnerable(args.url)
    else:
        with open(args.file, 'r') as file:
            process_urls(file.readlines())


if __name__ == "__main__":
    main()
