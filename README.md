# CVE-2023-3519 Inspector

The `cve_2023_3519_inspector.py` is a Python-based vulnerability scanner for detecting the CVE-2023-3519 vulnerability in Citrix Gateways. It performs a passive analysis and fingerprinting of target websites to assess their vulnerability based on a series of checks.

<img width="968" alt="image" src="https://github.com/securekomodo/citrixInspector/assets/4809643/f9186404-cc85-4ffb-89be-32b5f0db05ba">


### Recent Updates
- Added functionality to parse the /vpn/pluginlist.xml file to determine more accurate checks if patched or vulnerable
- Added funcionality to optionally check for common web shell IOCs on the target server.
- Implemented logic on scanner to determine if target is verified patched. Thanks @UK_Daniel_Card & @DTCERT

## Installation

This script requires Python 3.6+ and the following Python packages:

- requests
- BeautifulSoup4
- argparse
- re
- logging
- warnings

To install the required packages, run:

```bash
git clone https://github.com/securekomodo/citrixInspector.git
cd citrixInspector
pip install -r requirements.txt
python cve_2023_3519_inspector.py -u <target_url>
```

## Usage
```
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
    |   |/    \ /  ___/\____ \_/ __ \_/ ___\   __\/  _ \_  __ \
    |   |   |  \___ \ |  |_> >  ___/\  \___|  | (  <_> )  | \/
    |___|___|  /____  >|   __/ \___  >\___  >__|  \____/|__|   
             \/     \/ |__|        \/     \/                                

       CVE-2023-3519 Inspector
       ------------------------
       
usage: cve_2023_3519_inspector.py [-h] (-u URL | -f FILE) [--ioc-check] [-l LOG]

Check for vulnerabilities in Citrix Gateway.

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     The URL of the Citrix Gateway to check.
  -f FILE, --file FILE  A file containing a list of URLs to check.
  --ioc-check           Slower. Performs IOC (Indicator of Compromise) check.
  -l LOG, --log LOG     Log file to write the output.

```

The `cve_2023_3519_inspector.py` script can either accept a single URL or a file with a list of URLs as input. It then performs a series of checks to determine the potential vulnerability of the given Citrix Gateways:

```bash
# Check a single URL
python cve_2023_3519_inspector.py --url https://example.com

# Check multiple URLs from a file
python cve_2023_3519_inspector.py --file urls.txt

# Check multiple URLs from a file and check for IOCs
python cve_2023_3519_inspector.py --file urls.txt --ioc-check
```

To specify a log file for output, use the `--log` option:

```bash
python cve_2023_3519_inspector.py --url https://example.com --log my_log.log
```

For help:

```bash
python cve_2023_3519_inspector.py --help
```

## Checks Performed

The `cve_2023_3519_inspector.py` script performs the following checks on the target websites:

- Checks for the recent version of the pluginslist.xml file located at /vpn/pluginlist.xml
- (Optional) Check for the presence of common web shells known to be affiliated with exploitation in the wild
- Check if the HTTP title is "Citrix Gateway"
- Check for the presence of an HTML comment containing the text "frame-busting" which was found as an artifact on older/legacy citrix installations
- Check for the presence of specific icons associated with Citrix Gateway
- Check for the presence of specific vhashes in the HTML content. This is based off the amazing work from Fox It NCC Group back in 2022: https://blog.fox-it.com/2022/12/28/cve-2022-27510-cve-2022-27518-measuring-citrix-adc-gateway-version-adoption-on-the-internet/

Depending on the checks passed, the script infers if the target is a Citrix Gateway and if it is vulnerable and outputs the result to the console and optionally to a log file.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of citrixInspector/cve_2023_3519_inspector for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

## License
The project is licensed under MIT License.

## Author
Bryan Smith

- Twitter: https://twitter.com/securekomodo
- Bugcrowd/Hackerone: @d4rkm0de

---
