#!/usr/bin/env python3
# coding=utf-8
#
# citrixInspector.py
#
# AUTHOR
# Bryan Smith (@securekomodo)
#
# Passive fingerprinting & vulnerability inspector for Citrix ADC / Citrix Gateway /
# NetScaler ADC / NetScaler Gateway appliances.
#
# Originally focused solely on CVE-2023-3519. Now identifies the exact firmware build
# (where possible) via two unauthenticated fingerprinting techniques pioneered by the
# Fox-IT Security Research Team, and reports every known CVE affecting that build:
#   - GZIP MTIME timestamp of /vpn/js/rdx/core/lang/rdx_en.json.gz (primary, most reliable)
#   - Legacy "vhash" (v=<md5>) query string embedded in static resource URLs (secondary,
#     not always present on modern builds)
# See the "Checks Performed" and "Credits & Data Sources" sections of README.md for
# full details & sources.


import argparse
import requests
from bs4 import BeautifulSoup
import re
import logging
import warnings
import sys
import subprocess
import pkg_resources
import datetime
from typing import NamedTuple, Optional
from xml.etree import ElementTree as ET
from urllib.parse import urlparse

# How many checks per URL
MAX_RETRIES = 5

# Check if the OpenSSL version is the one required
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


# Legacy CVE-2023-3519 patch heuristic based on the main page's HTTP Last-Modified header.
# Kept as a last-resort signal for targets where no exact build can be identified via the
# vhash / GZIP-timestamp techniques below.
# THANKS https://github.com/telekom-security/cve-2023-3519-citrix-scanner/blob/main/CVE-2023-3519-checker.py
PATCHED_VERSIONS = [
    {"version": "13.0-91.13", "timestamp": "Fri, 07 Jul 2023 15:39:40 GMT"},
    {"version": "13.1-49.13", "timestamp": "Mon, 10 Jul 2023 17:41:17 GMT"},
    {"version": "13.1-49.13", "timestamp": "Mon, 10 Jul 2023 18:36:14 GMT"}
]

# some common web shell names and some IOCs mandiant discovered
POTENTIALLY_COMPROMISED_FILES = [
    "alfav3-encoded.php",
    "alfav4.1-decoded.php",
    "alfav4.1-encoded.php",
    "andela.php",
    "bloodsecv4.php",
    "by.php",
    "c99ud.php",
    "cmd.php",
    "configkillerionkros.php",
    "mini.php",
    "obfuscated-punknopass.php",
    "punk-nopass.php",
    "punkholic.php",
    "r57.php",
    "smevk.php",
    "TwemlowsWebShell.php",
    "wso2.8.5.php",
    "insight-new-min.js",
    "info.php",
    "prod.php",
    "log.php",
    "logout.php",
    "vpn.php",
    "config.php",
    "shell.php",
    "poc.php",
    "rshell.php",
    "php-reverse-shell.php",
]

# ══════════════════════════════════════════════════════════════════════════════
#  VERSION FINGERPRINTING DATA (vhash + GZIP timestamp)
#  Source: Fox-IT Security Research Team, "citrix-netscaler-triage"
#    https://github.com/fox-it/citrix-netscaler-triage (Apache License 2.0)
#  Original blog & technique:
#    https://blog.fox-it.com/2022/12/28/cve-2022-27510-cve-2022-27518-measuring-citrix-adc-gateway-version-adoption-on-the-internet/
#
#  VHASH_TO_VERSION: the legacy "v=<md5>" query string appended to static resource URLs
#  in the HTML response (e.g. /vpn/js/rdx/core/css/rdx.css?v=<hash>). Per Fox-IT: "the
#  version hash is not always present anymore since our blog", so treat this as a
#  secondary signal.
# ══════════════════════════════════════════════════════════════════════════════
VHASH_TO_VERSION = {
    "26df0e65fba681faaeb333058a8b28bf": "12.1-50.28",
    "d3b5c691a4cfcc6769da8dc4e40f511d": "12.1-50.31",
    "995a76005c128f4e89474af12ac0de66": "12.1-51.16",
    "d2bd166fed66cdf035a0778a09fd688c": "12.1-51.19",
    "86b4b2567b05dff896aae46d6e0765bc": "13.0-36.27",
    "43a8abf580ea09a5fa8aa1bd579280b9": "13.0-41.20",
    "7116ed70ec000da9267a019728ed951e": "13.0-41.28",
    "8c62b39f7068ea2f3d3f7d40860c0cd4": "12.1-55.13",
    "fedb4ba86b5edcbc86081f2893dc9fdf": "13.0-47.22",
    "02d30141fd053d5c3448bf04fbedb8d6": "12.1-55.18",
    "fd96bc8977256003de05ed84270b90bb": "13.0-47.24",
    "f787f9a8c05a502cd33f363e1e9934aa": "12.1-55.24",
    "e79f3bbf822c1fede6b5a1a4b6035a41": "13.0-52.24",
    "f2db014a3eb9790a19dfd71331e7f5d0": "12.1-56.22",
    "fdf2235967556bad892fbf29ca69eefd": "13.0-58.30",
    "4ecb5abf6e4b1655c07386a2c958597c": "12.1-57.18",
    "dcb06155d51a0234e9d127658ef9f21f": "13.0-58.32",
    "12c4901ecc3677aad06f678be49cb837": "13.0-61.48",
    "bf898768ad1e1d477fa649711c72c6df": "13.0-61.48",
    "a1494e2e09cb96e424c6c66512224941": "12.1-58.14",
    "b1b38debf0e55c285c72465da3715034": "12.1-58.15",
    "06fbfcf525e47b5538f856965154e28c": "13.0-64.35",
    "7a0c8874e93395c5e4f1ef3e5e600a25": "12.1-59.16",
    "a8e0eb4a1b3e157e0d3a5e57dc46fd35": "13.0-67.39",
    "0aef7f8e9ea2b528aa2073f2875a28b8": "12.1-55.190",
    "f1eb8548a4f1d4e565248d4db456fffe": "12.1-60.16",
    "e2444db11d0fa5ed738aa568c2630704": "13.0-67.43",
    "3a65afd164db6f39aa41f5729001d257": "13.0-67.43",
    "9b545e2e4d153348bce08e3923cdfdc1": "13.0-71.40",
    "25ad60e92a33cbb5dbd7cd8c8380360d": "13.0-71.44",
    "0b516b768edfa45775c4be130c4b96b5": "12.1-60.19",
    "b3deb35b8a990a71acca052fd1e6e6e1": "12.1-55.210",
    "83e486e7ee7eb07ab88328a51466ac28": "12.1-61.18",
    "454d4ccdefa1d802a3f0ca474a2edd73": "13.0-76.29",
    "08ff522057b9422863dbabb104c7cf4b": "12.1-61.19",
    "648767678188e1567b7d15eee5714220": "13.0-76.31",
    "ce5da251414abbb1b6aed6d6141ed205": "12.1-61.19",
    "5e55889d93ff0f13c39bbebb4929a68e": "13.0-79.64",
    "35389d54edd8a7ef46dadbd00c1bc5ac": "12.1-62.21",
    "8e4425455b9da15bdcd9d574af653244": "12.1-62.23",
    "73952bdeead9629442cd391d64c74d93": "13.0-82.41",
    "25169dea48ef0f939d834468f3c626d2": "13.0-82.42",
    "efb9d8994f9656e476e80f9b278c5dae": "12.1-62.25",
    "e1ebdcea7585d24e9f380a1c52a77f5d": "12.1-62.27",
    "eb3f8a7e3fd3f44b70c121101618b80d": "13.0-82.45",
    "98a21b87cc25d486eb4189ab52cbc870": "13.1-4.43",
    "c9e95a96410b8f8d4bde6fa31278900f": "13.0-83.27",
    "394e3fa5ffce140c9dd4bedc38ddefa7": "13.1-9.52",
    "f3d4041188d723fec4547b1942ffea93": "12.1-63.22",
    "158c7182df4973f1f5346e21e9d97a01": "13.1-4.44",
    "a66c02f4d04a1bd32bfdcc1655c73466": "13.0-83.29",
    "5cd6bd7d0aec5dd13a1afb603111733a": "12.1-63.23",
    "645bded68068748e3314ad3e3ec8eb8f": "13.1-9.60",
    "7277ec67fd822b7dae3399aa71786a0a": "13.1-9.107",
    "e8ff095e03a3efcff7ed851bfb9141e5": "13.1-9.112",
    "5112d5394de0cb5f6d474e032a708907": "13.1-12.50",
    "3a316d2de5362e9f76280b3157f48d08": "13.0-84.10",
    "bb71c656f6b4e0e1573c77c6536397c3": "13.1-12.103",
    "ee44bd3bc047aead57bc000097e3d8aa": "12.1-63.24",
    "2b46554c087d2d5516559e9b8bc1875d": "13.0-84.11",
    "cf9d354b261231f6c6121058ba143af7": "13.1-12.51",
    "c6bcd2f119d83d1de762c8c09b482546": "12.1-64.16",
    "b3fb0319d5d2dad8c977b9986cc26bd8": "12.1-55.265",
    "0f3a063431972186f453e07954f34eb8": "13.1-17.42",
    "e42d7b3cf4a6938aecebdae491ba140c": "13.0-85.15",
    "71ad6c771d99d846195b67c30bfb0433": "13.1-12.117",
    "2edf0f445b69b2e322e80dbc3f6f711c": "12.1-55.276",
    "b4ac9c8852a04234f38d73d1d8238d37": "13.1-21.50",
    "9f73637db0e0f987bf7825486bfb5efe": "12.1-55.278",
    "c212a67672ef2da5a74ecd4e18c25835": "12.1-64.17",
    "fbdc5fbaed59f858aad0a870ac4a779c": "12.1-65.15",
    "e24224ce907593aaadd243831b51dbd7": "13.1-12.130",
    "1884e7877a13a991b6d3fac01efbaf79": "13.0-85.19",
    "853edb55246c138c530839e638089036": "13.1-24.38",
    "7a45138b938a54ab056e0c35cf0ae56c": "13.0-86.17",
    "4434db1ec24dd90750ea176f8eab213c": "12.1-65.17",
    "469591a5ef8c69899320a319d5259922": "12.1-55.282",
    "adc1f7c850ca3016b21776467691a767": "13.1-27.59",
    "8f1767a6961f7b797d318d884dbb3a9c": "13.1-12.131",
    "1f63988aa4d3f6d835704be50c56788a": "13.0-87.9",
    "57d9f58db7576d6a194d7dd10888e354": "13.1-30.52",
    "8c6bef3b4f16d6c9bfc2913aae2535d1": "13.1-30.103",
    "f214d9aa6ff8f43fdb17ce81caac723f": "13.1-30.105",
    "7afe87a42140b566a2115d1e232fdc07": "13.1-33.47",
    "8cbccac1a96eee108ae3c85bf9ff845a": "13.1-30.108",
    "212fa0e7b3a5ca540f156caceba507fe": "13.1-30.109",
    "29adf2b509250b780bac083577c92b45": "13.1-30.111",
    "c1b64cea1b80e973580a73b787828daf": "12.1-65.21",
    "4d817946cef53571bc303373fd6b406b": "12.1-55.289",
    "aff0ad8c8a961d7b838109a7ee532bcb": "13.1-33.49",
    "37c10ac513599cf39997d52168432c0e": "13.0-88.12",
    "27292ddd74e24a311e4269de9ecaa6e7": "13.0-88.13",
    "5e939302a9d7db7e35e63a39af1c7bec": "13.1-33.51",
    "6e7b2de88609868eeda0b1baf1d34a7e": "13.0-88.14",
    "56672635f81a1ce1f34f828fef41d2fa": "13.1-33.52",
    "9bf6d5d3131495969deba0f850447947": "13.1-33.54",
    "3bd7940b6425d9d4dba7e8b656d4ba65": "13.0-88.16",
    "0d656200c32bb47c300b81e599260c42": "13.1-37.38",
    "953fae977d4baedf39e83c9d1e134ef1": "12.1-55.291",
    "f063b04477adc652c6dd502ac0c39a75": "12.1-65.25",
    "c0c00b7caed367b1569574e4982294c5": "13.1-30.114",
    "14c6a775edda324764a940cfd3da48cb": "13.0-89.7",
    "c2b8537eb733844f1e0cc4f63210d016": "13.0-90.7",
    "b4c220db03ea18bc2eebb40e9ad3f4f8": "13.1-42.47",
    "0b2a3cb74b5c6adbe28827e8b76a9f64": "12.1-55.296",
    "6925fba74320b9bfb960299f7c3e7cce": "13.1-45.61",
    "cdb72bd7677da8af9942897256782c9b": "13.1-37.150",
    "281b46a105662de06fb259293aa79f2a": "13.0-90.11",
    "1487b55f253ea54b1d3603cc1212f164": "13.1-45.62",
    "a6a783263968040a97e44d7cac55eda6": "12.1-65.35",
    "d72c9f2af7ccded704862da7486cfef2": "13.1-45.63",
    "14195083e08df261613408eb5cf3b212": "13.1-45.64",
    "4d63b52cc99fe712f9be5e4795c854e9": "13.0-90.12",
    "46d83b1a2981c1cfefe8d3063adf78f4": "13.1-37.159",
    "28e592a607e8919cc6ca7dec63590e04": "12.1-55.297",
    "e1aa8ba6d7e558d43f0369d9b81cbb1c": "12.1-65.37",
    "155a75fb7efac3347e7362fd23083aa5": "12.1-55.300",
    "f6beac6ccd073f5f7c1a64c4c7e24c7e": "12.1-55.302",
    "9debca402a9fae56a0d5e0979f685cf2": "12.1-65.39",
    "08604a97f08f6973502adb8ebf78e0b0": "12.1-55.304",
    "fe1071e2b14a5b5016d3eb57ddcfc86d": "12.1-55.304",
    "c9d805972fbf558cf7a229db44632fa7": "12.1-55.307",
    "550d960eff41e3a6342b95c7ad149148": "12.1-55.309",
    "a7c411815373059b33b4d83bed6145a2": "12.1-55.321",
    "0dd3f401dd33679f07e06961db10a298": "12.1-55.321",
    "c624dcce8d3355d555021d2aac5f9715": "12.1-55.325",
    "423fd15327ae1326fd97733652441907": "12.1-55.325",
    "89929af92ff35a042d78e9010b7ec534": "12.1-55.328",
    "f069136a9297a52b6d86a5de987d9323": "12.1-55.328",
    "765c645f7af4a1ef5c11d464fafc6244": "12.1-55.330",
    "a53b1af56a97019171ec39665fedc54a": "12.1-55.330",
    "11ba0524227f5450bc03fb70ed17c3d5": "12.1-55.333",
}

# RDX_GZIP_STAMP_TO_VERSION: the GZIP MTIME (bytes 4-8 of the GZIP header, RFC 1952)
# of /vpn/js/rdx/core/lang/rdx_en.json.gz, set at firmware compile time. This is the
# primary, most reliable unauthenticated version-fingerprinting technique available
# today, and is unaffected by the vhash no longer being served on modern builds.
RDX_GZIP_STAMP_TO_VERSION = {
    1535167752: "12.1-49.23",
    1539712460: "12.1-49.37",
    1543395386: "12.1-50.28",
    1547833294: "12.1-50.31",
    1551259802: "12.1-51.16",
    1553553428: "12.1-51.19",
    1557769307: "13.0-36.27",
    1568102085: "13.0-41.20",
    1570800276: "13.0-41.28",
    1572931127: "12.1-55.13",
    1574967982: "13.0-47.22",
    1579181764: "11.1-63.15",
    1579524387: "12.1-55.18",
    1579525745: "13.0-47.24",
    1582900076: "12.1-55.24",
    1584639643: "13.0-52.24",
    1585473032: "12.1-56.22",
    1590994121: "13.0-58.30",
    1591024587: "12.0-63.21",
    1591064853: "11.1-64.14",
    1591729615: "12.1-57.18",
    1593707893: "13.0-58.32",
    1595447367: "13.0-61.48",
    1596099904: "13.0-61.48",
    1597416844: "12.1-58.14",
    1598960821: "12.1-58.15",
    1598976896: "13.0-64.35",
    1599733618: "11.1-65.12",
    1600737705: "12.1-59.16",
    1602086829: "13.0-67.39",
    1602147782: "12.1-55.190",
    1604484881: "12.1-60.16",
    1605272190: "13.0-67.43",
    1606224413: "13.0-67.43",
    1606972406: "13.0-71.40",
    1609009448: "13.0-71.44",
    1609011565: "12.1-60.19",
    1609729665: "12.1-55.210",
    1612272966: "12.1-61.18",
    1613673469: "13.0-76.29",
    1615224221: "12.1-61.19",
    1615281639: "13.0-76.31",
    1615477570: "12.1-61.19",
    1617632002: "13.0-79.64",
    1620657482: "12.1-62.21",
    1621266971: "12.1-62.23",
    1622313211: "11.1-65.20",
    1622469918: "13.0-82.41",
    1623352880: "13.0-82.42",
    1623368345: "12.1-62.25",
    1625622338: "12.1-62.27",
    1625638831: "11.1-65.22",
    1626453956: "13.0-82.45",
    1631259090: "13.1-4.43",
    1632751280: "13.0-83.27",
    1633526754: "13.1-9.52",
    1634064549: "11.1-65.23",
    1634113449: "12.1-63.22",
    1636641773: "13.1-4.44",
    1636650155: "13.0-83.29",
    1636661207: "12.1-63.23",
    1637163803: "13.1-9.60",
    1637905276: "13.1-9.107",
    1638969245: "13.1-9.112",
    1639153035: "13.1-12.50",
    1639162109: "13.0-84.10",
    1639730895: "13.1-12.103",
    1640166898: "12.1-63.24",
    1640186329: "13.0-84.11",
    1640248123: "13.1-12.51",
    1642646201: "12.1-64.16",
    1643350935: "12.1-55.265",
    1645447769: "13.1-17.42",
    1646925462: "13.0-85.15",
    1648241342: "13.1-12.117",
    1648963108: "12.1-55.276",
    1649311904: "13.1-21.50",
    1650526474: "12.1-55.278",
    1650537528: "12.1-64.17",
    1650655111: "12.1-65.15",
    1652100881: "13.1-12.130",
    1652947813: "13.0-85.19",
    1653569469: "13.1-24.38",
    1655226228: "13.0-86.17",
    1656510368: "12.1-65.17",
    1657097682: "12.1-55.282",
    1657104103: "13.1-27.59",
    1657655579: "13.1-12.131",
    1659116392: "13.0-87.9",
    1661353021: "13.1-30.52",
    1662371872: "13.1-30.103",
    1662553033: "13.1-30.105",
    1663959215: "13.1-33.47",
    1664281882: "13.1-30.108",
    1664513221: "13.1-30.109",
    1664885015: "13.1-30.111",
    1664899863: "12.1-65.21",
    1665559544: "12.1-55.289",
    1665594088: "13.1-33.49",
    1665767445: "13.0-88.12",
    1667231699: "13.0-88.13",
    1667233903: "13.1-33.51",
    1667452925: "13.0-88.14",
    1667453909: "13.1-33.52",
    1668678940: "13.1-33.54",
    1668681438: "13.0-88.16",
    1669203751: "13.1-37.38",
    1669636505: "12.1-55.291",
    1669808545: "12.1-65.25",
    1669891705: "13.1-30.114",
    1671033279: "13.0-89.7",
    1674582275: "13.0-90.7",
    1677072689: "13.1-42.47",
    1680677853: "12.1-55.296",
    1681286714: "13.1-45.61",
    1681754964: "13.1-37.150",
    1681918478: "13.0-90.11",
    1682509375: "13.1-45.62",
    1682714340: "12.1-65.35",
    1682844871: "13.1-45.63",
    1683866996: "13.0-91.12",
    1683876838: "13.1-45.64",
    1684146224: "13.0-90.12",
    1685777750: "13.1-48.47",
    1688743976: "13.0-91.13",
    1688746627: "13.1-37.159",
    1688747367: "12.1-55.297",
    1688954279: "13.1-49.101",
    1689014191: "13.1-49.13",
    1689059677: "13.1-49.102",
    1689827785: "13.1-49.106",
    1690503901: "14.1-4.42",
    1693379034: "13.0-92.18",
    1694760036: "14.1-8.50",
    1695273924: "13.0-92.19",
    1695277021: "13.1-49.15",
    1695284102: "12.1-65.37",
    1695316368: "12.1-55.300",
    1695817672: "13.1-37.164",
    1697614024: "13.1-50.23",
    1700677179: "14.1-12.30",
    1701886543: "14.1-8.120",
    1702035068: "14.1-12.34",
    1702062640: "13.1-51.14",
    1702548756: "13.0-92.21",
    1702625218: "13.1-51.15",
    1702631914: "14.1-12.35",
    1702886392: "12.1-55.302",
    1702908964: "12.1-65.39",
    1704194696: "14.1-8.122",
    1704428153: "13.1-37.176",
    1707370491: "14.1-17.38",
    1709227868: "13.1-52.19",
    1713474810: "14.1-21.57",
    1714132594: "12.1-55.304",
    1714542524: "12.1-55.304",
    1715618728: "13.1-53.17",
    1715691351: "13.1-37.183",
    1717831730: "14.1-25.53",
    1718215257: "12.1-55.307",
    1718362054: "13.1-37.188",
    1719233060: "14.1-25.107",
    1720089675: "13.0-92.31",
    1720103560: "13.1-53.24",
    1720110688: "14.1-25.56",
    1720111773: "13.1-37.190",
    1720159658: "14.1-25.108",
    1720464791: "13.0-92.31",
    1720473719: "12.1-55.309",
    1721238815: "13.1-54.29",
    1723114781: "14.1-29.63",
    1723549420: "13.1-37.199",
    1726488799: "13.1-55.29",
    1728331888: "13.1-37.207",
    1728334533: "12.1-55.321",
    1728642184: "14.1-29.72",
    1729543935: "12.1-55.321",
    1729561034: "14.1-34.42",
    1729777429: "13.1-55.34",
    1730184925: "14.1-34.101",
    1730996230: "13.1-56.18",
    1732875663: "13.1-37.219",
    1734369608: "14.1-38.53",
    1737799969: "13.1-57.26",
    1739236765: "12.1-55.325",
    1739840877: "12.1-55.325",
    1740156084: "14.1-43.50",
    1741267150: "14.1-34.105",
    1741944779: "14.1-34.107",
    1743497009: "13.1-37.232",
    1744121299: "13.1-58.21",
    1744185164: "14.1-43.109",
    1747159096: "14.1-47.40",
    1747727322: "14.1-47.43",
    1747814734: "14.1-47.44",
    1749304395: "14.1-47.46",
    1749552827: "14.1-43.56",
    1749564145: "12.1-55.328",
    1749572802: "13.1-37.235",
    1749588747: "13.1-58.32",
    1750134083: "12.1-55.328",
    1750251851: "13.1-59.19",
    1755692465: "12.1-55.330",
    1755692615: "14.1-47.48",
    1755693334: "13.1-37.241",
    1755693886: "13.1-59.22",
    1756174950: "12.1-55.330",
    1756797107: "14.1-51.72",
    1756913056: "13.1-60.26",
    1756934296: "13.1-37.246",
    1758114017: "13.1-37.247",
    1758481087: "13.1-60.29",
    1758572828: "14.1-51.80",
    1760549260: "14.1-56.71",
    1761904279: "13.1-37.250",
    1761935980: "13.1-60.32",
    1762655407: "14.1-56.74",
    1762663520: "13.1-61.23",
    1762830097: "12.1-55.333",
}

CITRIX_ICON_LOCATIONS = [
    "/receiver/images/common/icon_vpn.ico",
    "/vpn/images/AccessGateway.ico",
]


# ══════════════════════════════════════════════════════════════════════════════
#  VERSION COMPARISON HELPERS
#  Ported from Fox-IT Security Research Team's "citrix-netscaler-triage" project
#  (Apache License 2.0): https://github.com/fox-it/citrix-netscaler-triage
# ══════════════════════════════════════════════════════════════════════════════

class VersionTuple(NamedTuple):
    major: int
    minor: int
    build: int
    patch: int


def parse_version(version: str) -> VersionTuple:
    """Convert a version string such as "13.1-49.13" into a VersionTuple.

    Raises ValueError if the version string cannot be parsed.
    """
    if not version or version == "unknown":
        raise ValueError(f"Invalid version: {version}")
    try:
        major, minor, build, patch = map(int, version.replace(".", "-").split("-"))
    except ValueError:
        raise ValueError(f"Invalid version: {version}")
    return VersionTuple(major, minor, build, patch)


def is_fips_13_1(v: VersionTuple) -> bool:
    """Return True if the version is the 13.1-FIPS / 13.1-NDcPP build track."""
    return (v.major, v.minor, v.build) == (13, 1, 37)


def is_fips_12_1(v: VersionTuple) -> bool:
    """Return True if the version is the 12.1-FIPS / 12.1-NDcPP build track."""
    return (v.major, v.minor, v.build) == (12, 1, 55)


def is_eol(v: VersionTuple) -> bool:
    """Return True if the branch is End-Of-Life (12.1 non-FIPS, 13.0, or older).

    NetScaler ADC/Gateway 12.1-FIPS and 13.1-FIPS remain supported branches.
    """
    if is_fips_13_1(v) or is_fips_12_1(v):
        return False
    if v.major == 13 and v.minor == 0:
        return True
    if v.major <= 12:
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  CVE VERSION-THRESHOLD CHECKS
#
#  Each function returns True if the given (build-identified) version is vulnerable.
#  All EOL branches (11.1, 12.1 non-FIPS, 13.0) are treated as unpatched/vulnerable to
#  every CVE released after their end-of-life date, since no fix was ever backported.
# ══════════════════════════════════════════════════════════════════════════════

def is_vuln_cve_2023_3519(v: VersionTuple) -> bool:
    """CVE-2023-3519: unauthenticated RCE (stack buffer overflow).

    Fixed in 13.0-91.13 and 13.1-49.13. NetScaler 14.1 did not exist until after the fix
    shipped (first 14.1 build was 14.1-4.42, released 28 Jul 2023) so it is never affected.
    12.1 / 11.1 (including their FIPS/NDcPP tracks) never received a fix for this CVE.
    Source: CTX561482.
    """
    if v.major == 14:
        return False
    if v.major == 13 and v.minor == 0:
        return v < VersionTuple(13, 0, 91, 13)
    if v.major == 13 and v.minor == 1:
        return v < VersionTuple(13, 1, 49, 13)
    return True


def is_vuln_ctx693420(v: VersionTuple) -> bool:
    """CVE-2025-5349 / CVE-2025-5777 ("CitrixBleed 2"): memory disclosure.

    Fixed in 14.1-43.56 / 13.1-58.32 / FIPS 13.1-37.235 / FIPS 12.1-55.328.
    Source: CTX693420, https://github.com/fox-it/citrix-netscaler-triage
    """
    if is_fips_13_1(v):
        return v < VersionTuple(13, 1, 37, 235)
    if is_fips_12_1(v):
        return v < VersionTuple(12, 1, 55, 328)
    if v.major == 14:
        return v < VersionTuple(14, 1, 43, 56)
    if v.major == 13:
        return v < VersionTuple(13, 1, 58, 32)
    return is_eol(v)


def is_vuln_ctx694788(v: VersionTuple) -> bool:
    """CVE-2025-6543: memory overflow on Gateway virtual servers, exploited in the wild.

    Fixed in 14.1-47.46 / 13.1-59.19 / FIPS 13.1-37.236. FIPS 12.1 is not affected.
    Source: CTX694788, https://github.com/fox-it/citrix-netscaler-triage
    """
    if is_fips_13_1(v):
        return v < VersionTuple(13, 1, 37, 236)
    if is_fips_12_1(v):
        return False
    if v.major == 14:
        return v < VersionTuple(14, 1, 47, 46)
    if v.major == 13:
        return v < VersionTuple(13, 1, 59, 19)
    return is_eol(v)


def is_vuln_ctx694938(v: VersionTuple) -> bool:
    """CVE-2025-7775 / CVE-2025-7776 / CVE-2025-8424 ("CitrixBleed 3").

    Fixed in 14.1-47.48 / 13.1-59.22 / FIPS 13.1-37.241 / FIPS 12.1-55.330.
    Source: CTX694938, https://github.com/fox-it/citrix-netscaler-triage
    """
    if is_fips_13_1(v):
        return v < VersionTuple(13, 1, 37, 241)
    if is_fips_12_1(v):
        return v < VersionTuple(12, 1, 55, 330)
    if v.major == 14:
        return v < VersionTuple(14, 1, 47, 48)
    if v.major == 13:
        return v < VersionTuple(13, 1, 59, 22)
    return is_eol(v)


def is_vuln_cve_2026_8452(v: VersionTuple) -> bool:
    """CVE-2026-8452: pre-auth SAML PrefixList heap overflow (CTX696604).

    Requires a SAML SP or IdP policy bound to the target virtual server. Fixed in
    14.1-72.61 / 13.1-63.18. 12.1 and 13.0 are EOL and were never fixed.
    Source: CTX696604, watchTowr Labs
    (https://labs.watchtowr.com/youre-back-in-the-room-citrix-netscaler-pre-auth-rce-cve-2026-8452/)
    and BishopFox (https://github.com/BishopFox/CVE-2026-8452-check).
    """
    if v.major == 14:
        return v < VersionTuple(14, 1, 72, 61)
    if v.major == 13 and v.minor == 1:
        return v < VersionTuple(13, 1, 63, 18)
    return is_eol(v)


def is_vuln_ctx697096(v: VersionTuple) -> bool:
    """CVE-2026-88771 (pre-auth command injection, default config) and CVE-2026-88772
    (DTLS memory overflow). Both actively exploited in the wild and listed in CISA KEV.

    Fixed in 14.1-73.37 / 13.1-64.23 / FIPS 14.1-73.37 / FIPS-NDcPP 13.1-37.279.
    12.1, 13.0 and older releases are EOL and were never fixed for this bulletin.
    Source: CTX697096; watchTowr Labs
    (https://labs.watchtowr.com/oh-look-the-foot-gun-went-off-again-citrix-netscaler-preauth-command-injection-cve-2026-88771/).
    """
    if is_fips_13_1(v):
        return v < VersionTuple(13, 1, 37, 279)
    if v.major == 14:
        return v < VersionTuple(14, 1, 73, 37)
    if v.major == 13 and v.minor == 1:
        return v < VersionTuple(13, 1, 64, 23)
    return True


# Registry of every CVE this tool can identify from a fingerprinted version, together
# with a short human-readable description used in report output.
CVE_CHECKS = {
    "CVE-2023-3519": (is_vuln_cve_2023_3519, "Unauthenticated RCE (stack overflow)"),
    "CVE-2025-5349": (is_vuln_ctx693420, "CitrixBleed 2 - memory disclosure"),
    "CVE-2025-5777": (is_vuln_ctx693420, "CitrixBleed 2 - memory disclosure"),
    "CVE-2025-6543": (is_vuln_ctx694788, "Memory overflow (Gateway), exploited in the wild"),
    "CVE-2025-7775": (is_vuln_ctx694938, "CitrixBleed 3 - memory overflow"),
    "CVE-2025-7776": (is_vuln_ctx694938, "CitrixBleed 3 - memory overflow"),
    "CVE-2025-8424": (is_vuln_ctx694938, "CitrixBleed 3 - access control issue"),
    "CVE-2026-8452": (is_vuln_cve_2026_8452, "Pre-auth SAML PrefixList heap overflow (requires SAML SP/IdP)"),
    "CVE-2026-88771": (is_vuln_ctx697096, "Pre-auth command injection, exploited in the wild (KEV)"),
    "CVE-2026-88772": (is_vuln_ctx697096, "DTLS memory overflow, exploited in the wild (KEV)"),
}


def get_vulnerable_cves(version: str):
    """Return a sorted list of CVE ids that the given version string is vulnerable to.

    Returns an empty list if the version is unparseable or not vulnerable to anything.
    """
    try:
        vtuple = parse_version(version)
    except ValueError:
        return []
    return sorted(cve for cve, (check, _desc) in CVE_CHECKS.items() if check(vtuple))



def check_pluginlist_xml(url):
    parsed_url = urlparse(url)
    site = f"{parsed_url.scheme}://{parsed_url.netloc}"
    logging.info(f"Making request to {site} to determine XML version")
    response = requests.get(f"{site}/vpn/pluginlist.xml", verify=False, allow_redirects=False, timeout=MAX_RETRIES)

    # check if request was successful
    if response.status_code == 200:
        root = ET.fromstring(response.content)

        # find the plugin
        for repository in root.findall('repository'):
            for plugin in repository.findall('plugin'):
                name = plugin.get('name')
                version = plugin.get('version')

                # check if this is the plugin we are interested in
                if name == "Netscaler Gateway EPA plug-in for Windows (32 bit)":
                    # extract the major version
                    major_version = int(version.split(".")[0])
                    minor_version = int(version.split(".")[1])

                    if major_version < 22:
                        logging.info(f"{site} - Matched Version: {version}")
                        return "VULNERABLE"
                    if major_version >= 23:
                        if minor_version >= 5:
                            logging.info(f"{site} - Matched Version: {version}")
                            return "PATCHED"
                    else:
                        logging.info(f"{site} - Version does not match: {version}")
    else:
        logging.info(f"{site} - Failed to fetch XML")



def is_site_compromised(url):
    parsed_url = urlparse(url)
    site = f"{parsed_url.scheme}://{parsed_url.netloc}"

    for ioc in POTENTIALLY_COMPROMISED_FILES:
        try:
            webshell_path = site + "/vpn/themes/" + ioc
            logging.info(f"Making request to {webshell_path} to determine if compromised")
            response = requests.get(webshell_path, verify=False, allow_redirects=False, timeout=MAX_RETRIES)
        except requests.exceptions.RequestException as e:
            logging.error(f"An error occurred while trying to connect to {webshell_path}. Error: {e}")
            return

        if response.status_code == 200:
            print(f"{webshell_path} - [COMPROMISE DETECTED]")
            logging.info(f"{webshell_path} is potentially compromised! Evidence of web shell observed!")
        elif response.status_code != 404:
            logging.info(f"{webshell_path} - Benign Result: {response.text}")


def check_rdx_gzip_timestamp(url) -> Optional[str]:
    """Fingerprint the exact NetScaler build via the GZIP MTIME of rdx_en.json.gz.

    This is Fox-IT's current primary version-fingerprinting technique (see the
    VHASH_TO_VERSION / RDX_GZIP_STAMP_TO_VERSION header comment for sources) and does
    not require decompressing the file: the GZIP header format (RFC 1952) stores the
    modification timestamp as a little-endian uint32 in bytes 4-7. That timestamp is
    set at firmware compile time, so it uniquely identifies the build.

    Returns the matched version string, or None if the resource is missing, not a
    valid GZIP file, has its timestamp stripped (MTIME=0), or the timestamp is not in
    our lookup table.
    """
    parsed_url = urlparse(url)
    site = f"{parsed_url.scheme}://{parsed_url.netloc}"
    gzip_path = f"{site}/vpn/js/rdx/core/lang/rdx_en.json.gz"

    try:
        logging.info(f"Making request to {gzip_path} to extract the GZIP build timestamp")
        response = requests.get(gzip_path, verify=False, allow_redirects=False, timeout=MAX_RETRIES)
    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while trying to connect to {gzip_path}. Error: {e}")
        return None

    if response.status_code != 200:
        logging.info(f"{gzip_path} - Failed to fetch GZIP resource (HTTP {response.status_code})")
        return None

    data = response.content
    # GZIP header: bytes 0-1 magic (1f 8b), byte 2 compression method, byte 3 flags,
    # bytes 4-7 MTIME (little-endian unix timestamp, 0 if not available).
    if len(data) < 8 or data[:2] != b"\x1f\x8b":
        logging.info(f"{gzip_path} - Not a valid GZIP resource")
        return None

    stamp = int.from_bytes(data[4:8], "little")
    if stamp == 0:
        logging.info(f"{gzip_path} - GZIP MTIME not set (timestamp stripped)")
        return None

    version = RDX_GZIP_STAMP_TO_VERSION.get(stamp)
    if version:
        logging.info(f"{url} - GZIP timestamp check Passed. Matched Version: {version} (stamp={stamp})")
    else:
        logging.info(f"{url} - GZIP timestamp {stamp} not present in lookup table")
    return version


def is_site_vulnerable(url):
    try:
        logging.info(f"Making request to {url}")
        response = requests.get(url, verify=False, timeout=MAX_RETRIES)
    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while trying to connect to {url}. Error: {e}")
        print(f"{url} - [UNREACHABLE]")
        return

    html_content = response.text

    soup = BeautifulSoup(html_content, 'html.parser')

    # Initialize checks
    title_check = False
    comment_check = False
    icon_check = False
    hash_exists = False
    identified_version = None
    patched = False
    header_check = False
    xml_check = False

    # Check if the title is "Citrix" related
    if soup.title.string in ["Citrix Gateway", "NetScaler AAA", "Digital Workplace", "NetScaler Gateway"]:
        title_check = True
        logging.info(f"{url} - Title Check Passed")

    # Check for "frame-busting" HTML comment
    if "frame-busting" in html_content:
        comment_check = True
        logging.info(f"{url} - HTML comment check Passed")

    # Check for icon
    icon_check = "/vpn/images/AccessGateway.ico" in html_content or "receiver/images/common/icon_vpn.ico" in html_content
    for icon in CITRIX_ICON_LOCATIONS:
        if icon in html_content:
            icon_check = True
            logging.info(f"{url} - Icon check Passed")

    # Check if a vhash is present in the HTML content (legacy technique, not always
    # present on modern builds - see VHASH_TO_VERSION header comment)
    pattern = r'v=([a-fA-F0-9]{32})'
    match = re.search(pattern, html_content)
    if match:
        hash_exists = True
        logging.info(f"{url} - Hash found")
        matched_version = VHASH_TO_VERSION.get(match.group(1))
        if matched_version:
            identified_version = matched_version
            logging.info(f"{url} - Version check Passed. Matched Version: {matched_version}")
    else:
        logging.info(f"{url} - Hash check Not Found")

    # GZIP-timestamp check (primary, most reliable technique - takes priority over vhash)
    gzip_version = check_rdx_gzip_timestamp(url)
    if gzip_version:
        identified_version = gzip_version

    # VPN Pluginlist XML Check
    xml_check = check_pluginlist_xml(url)
    if xml_check == "PATCHED" and not identified_version:
        patched = True

    vulnerable_cves = []
    if identified_version:
        # We know the exact build - determine every CVE it is vulnerable to instead of
        # relying on the coarse Last-Modified header heuristic below.
        vulnerable_cves = get_vulnerable_cves(identified_version)
        patched = not vulnerable_cves
    else:
        # No exact build identified - fall back to the legacy CVE-2023-3519-only
        # heuristic based on the main page's HTTP Last-Modified header, if present.
        # Not every target sends this header (e.g. non-Citrix hosts, proxies/WAFs that
        # strip it), so we degrade gracefully instead of crashing when it's missing or
        # unparseable.
        last_modified_header = response.headers.get("Last-Modified")
        last_modified = None
        if last_modified_header:
            try:
                last_modified = datetime.datetime.strptime(last_modified_header, "%a, %d %b %Y %H:%M:%S %Z")
            except ValueError:
                logging.info(f"{url} - Last-Modified header present but unparseable: {last_modified_header!r}")
        else:
            logging.info(f"{url} - No Last-Modified header present; skipping legacy header heuristic")

        if last_modified:
            for patch in PATCHED_VERSIONS:
                if last_modified == datetime.datetime.strptime(patch["timestamp"], "%a, %d %b %Y %H:%M:%S %Z"):
                    logging.info(f"{url} - Patch Check Passed. Not Vulnerable")
                    patched = True
                    identified_version = patch["version"]
                elif not patched and last_modified < datetime.datetime.strptime("01 Jul 2023 00:00:00 GMT", "%d %b %Y %H:%M:%S %Z"):
                    header_check = True
                    logging.info(f"{url} - Header Check Complete. potentially vulnerable (older than 01 Jul 2023)")
                elif not patched and "Jul 2023" in last_modified_header:
                    header_check = True
                    logging.info(f"{url} - Header Check Complete. Most Likely Patched (newer than 01 Jul 2023)")
                    identified_version = None
                    patched = True
        if identified_version:
            vulnerable_cves = get_vulnerable_cves(identified_version)
            patched = not vulnerable_cves

    # Decision making based on the checks
    status = ''
    message = ''

    if identified_version and vulnerable_cves:
        status = '[VULNERABLE]'
        message = f"[CERTAIN] [{', '.join(vulnerable_cves)}] [{identified_version}]"
    elif identified_version and patched:
        status = '[PATCHED]'
        message = f"[CERTAIN] [{identified_version}]"
    elif patched:
        status = '[PATCHED]'
        message = f"[FIRM]"
    elif (title_check and comment_check and icon_check and hash_exists and header_check) and not patched:
        # Note: identified_version always short-circuits into one of the two branches
        # above, so this is only reached when no vhash/gzip/pluginlist version could be
        # resolved but the legacy header heuristic still looks suspicious.
        status = '[VULNERABLE]'
        message = f"[FIRM]"
    elif (title_check and icon_check and xml_check) and not patched:
        status = '[VULNERABLE]'
        message = f"[TENTATIVE]"
    elif title_check and icon_check and not patched:
        status = '[CITRIX DETECTED]'
    else:
        message = f"[CITRIX NOT DETECTED]"

    if status == '[PATCHED]':
        logging.info(f"{url} - {status} {message}")
    elif status == '[VULNERABLE]':
        logging.warning(f"{url} - {status} {message}")
    else:
        logging.info(f"{url} - {message}")
    print(f"{url} - {status} {message}")

def process_urls(urls, iocs):
    print(f"Checking list if vulnerable to known Citrix ADC / NetScaler Gateway CVEs")
    if iocs:
        print(f"Checking list if compromised by CVE-2023-3519 (Be patient!)")
    for url in urls:
        if iocs:
            is_site_compromised(url.strip())
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

       citrixInspector
       ------------------------
       """)
    parser = argparse.ArgumentParser(description="Fingerprint and check Citrix ADC / NetScaler ADC & Gateway for known CVEs.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help="The URL of the Citrix/NetScaler Gateway to check.")
    group.add_argument('-f', '--file', help="A file containing a list of URLs to check.")
    parser.add_argument('--ioc-check', action='store_true', help='Slower. Performs IOC (Indicator of Compromise) check.')
    parser.add_argument('-l', '--log', default='citrixInspector.log', help="Log file to write the output.")
    args = parser.parse_args()

    logging.basicConfig(filename=args.log, filemode='w', format='%(message)s', level=logging.INFO)

    if args.url:
        timestamp = datetime.datetime.now()
        logging.info(f"Scan started: {timestamp}")
        print(f"Scan started: {timestamp}")
        print(f"{args.url} - Checking for known Citrix ADC / NetScaler Gateway CVEs")
        if args.ioc_check:
            print(f"{args.url} - Checking if compromised by CVE-2023-3519 (Be patient!)")
            is_site_compromised(args.url)
        is_site_vulnerable(args.url)
        timestamp = datetime.datetime.now()
        logging.info(f"Scan Complete: {timestamp}")
        print(f"Scan Complete: {timestamp}")
    else:
        timestamp = datetime.datetime.now()
        logging.info(f"Scan started: {timestamp}")
        print(f"Scan started: {timestamp}")
        with open(args.file, 'r') as file:
            if args.ioc_check:
                process_urls(file.readlines(), True)
            else:
                process_urls(file.readlines(), False)
        timestamp = datetime.datetime.now()
        logging.info(f"Scan Complete: {timestamp}")
        print(f"Scan Complete: {timestamp}")

if __name__ == "__main__":
    main()
