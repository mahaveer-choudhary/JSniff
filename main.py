import re
from requests import get, exceptions 
from urllib3 import disable_warnings 
from colorama import Fore, Style, init
from random import choice 
# from jsbeautifier import beautify
import jsbeautifier
from re import findall 
from rich.console import Console
from argparse import ArgumentParser 

init(autoreset=True)
disable_warnings()

## color codes for terminal
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

## importing user agents 
def get_user_agent() -> str: 
    """Return a random User-Agent from user_agents.txt file to be used in the requests"""

    file_path : str = 'modules/user_agents.txt'
    with open(file_path) as content: 
        user_agents: str = content.readlines()
        user_agent: str = choice(user_agents).strip()

        return user_agent 

## scan modules 
regex_list = {
    'Google API': r'AIza[0-9A-Za-z-_]{35}',
    "Artifactory API Token": r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}',
    "Artifactory Password": r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}',
    "Cloudinary Basic Auth": r"cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+",
    'Firebase Key': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    "LinkedIn Secret Key": r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]",
    "Mailto String": r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "Firebase URL": r".*firebaseio\.com",
    "PGP Private Key Block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "SSH (DSA) Private Key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "SSH (RSA) Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "SSH (ssh-ed25519) Public Key": r"ssh-ed25519",
    'Google Captcha Key': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    "Amazon AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Amazon MWS Auth Token": r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Amazon AWS API Key": r"AKIA[0-9A-Z]{16}",
    'Amazon AWS URL' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    "Generic API Key": r"(?i)api[_]?key.*['|\"]\w{32,45}['|\"]",
    "Generic Secret": r"(?i)secret.*['|\"]\w{32,45}['|\"]",
    'Authorization Bearer': r'bbearer [a-zA-Z0-9_\\-\\.=]+',
    'Authorization Basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'Authorization API Key' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'PayPal Braintree Access Token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'Mailgun API Key' : r'key-[0-9a-zA-Z]{32}',
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    'RSA Private Key' : r'-----BEGIN RSA PRIVATE KEY-----',
    "JWT Token": r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": r"(?i)facebook.*['|\"][0-9a-f]{32}['|\"]",
    "Google OAuth" : r'ya29\.[0-9A-Za-z\-_]+',
    "Facebook Client ID": r"""(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}""",
    "Google Cloud Platform API Key": r"(?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|\"|\n|\r|\s|\x60]|$)",
    "Google Cloud Platform OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google Drive API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google Drive OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google (GCP) Service-account": r"\"type\": \"service_account\"",
    "Google Gmail API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google Gmail OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google OAuth Access Token": r"ya29\\.[0-9A-Za-z\\-_]+",
    "Google YouTube API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google YouTube OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    'GitHub Access Token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    "GitHub Personal Access Token": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub URL": r"(?i)github.*['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "GitHub App Token": r"(ghu|ghs)_[0-9a-zA-Z]{36}",
    "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "Slack Webhook": r"https://hooks.slack.com/services/T\w{8}/B\w{8}/\w{24}",
    "Slack Webhook 2": r"T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Slack OAuth v2 Username/Bot Access Token": r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
    "Slack OAuth v2 Configuration Token": r"xoxe.xoxp-1-[0-9a-zA-Z]{166}",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Twitter Access Token": r"(?i)twitter.*[1-9][0-9]+-\w{40}",
    "Twitter OAuth": r"(?i)twitter.*['|\"]\w{35,44}['|\"]",
    "Twitter Client ID": r"(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}",
    "URL Parameter": r"(?<=\?|\&)[a-zA-Z0-9_]+(?=\=)",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\\-_]{43}",
    "URL": r'(https?|ftp)://(-\.)?([^\s/?\.#-]+\.?)+(/[^\s]*)?$iS',
    "Adobe Client Secret": r'''(?i)\b((p8e-)[a-zA-Z0-9]{32})(?:['|\"|\n|\r|\s|\x60]|$)''',
    "Alibaba AccessKey ID": r"(?i)\b((LTAI)[a-zA-Z0-9]{20})(?:['|\"|\n|\r|\s|\x60]|$)",
    "Clojars API Token": r"(?i)(CLOJARS_)[a-z0-9]{60}",
    "Doppler API Token": r"(dp\.pt\.)[a-zA-Z0-9]{43}",
    "Dynatrace API Token": r"dt0c01\.[a-zA-Z0-9]{24}\.[a-z0-9]{64}",
    "EasyPost API Token": r"EZAK[a-zA-Z0-9]{54}",
    "GitLab Personal Access Token": r"glpat-[0-9a-zA-Z\-\_]{20}",
    "NPM Access Token": r"(?i)\b(npm_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60]|$)",
    "Shopify Private APP Access Token": r"shppa_[a-fA-F0-9]{32}",
    "Shopify Shared Secret": r"shpss_[a-fA-F0-9]{32}",
    "Shopify Custom Access Token": r"shpca_[a-fA-F0-9]{32}",
    "Shopify Access Token": r"shpat_[a-fA-F0-9]{32}",
    "Asana Client ID": r"""(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)""",
    "Asana Client Secret": r"""(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)"""
}

def scan(url, custom_headers) -> None: 
    """ Open JavaScript file without parsing URL before requesting"""

    try : 
        response = get(url, headers=custom_headers, timeout=30)
        content = jsbeautifier.beautify(response.text) 

        for key, pattern in regex_list.items(): 
            matches = findall(pattern, content) 
            if matches: 
                print(f"\n{GREEN}{RESET} {YELLOW}{key}{RESET} found in {CYAN}{url}{RESET}: {matches}\n")

    except Exception as e : 
        print(f"{RED}[!] Error scanning {url}: {e}{RESET}")


def perform_check(args): 
    """Check if target is accessible"""
    url = args.url 
    custom_headers = {
        "User-Agent" : get_user_agent(),
    }

    for header in args.HEADER: 
        name, value = header
        custom_headers[name] = value

    try : 
        response = get(url, headers=custom_headers, verify=False)
        status_code = response.status_code
        page_content = response.text

        if(response.ok):
            print(f"{GREEN}[+]{RESET} Connected Successfully with {Fore.YELLOW}{url}{Style.RESET_ALL}")
            extract_js(url, page_content, custom_headers)

        else : 
            print(f"{RED}[!]{RESET} {url} returned {status_code} status code{Style.RESET_ALL}")
            return False
        
    except exceptions.ConnectionError as con_error: 
        print(f"{RED}[!]{RESET} {url} {RED}Connection Error:{RESET} {con_error}")

    except exceptions.InvalidURL as invalid_error: 
        print(f"{RED}[!]{RESET} Invalid URL {url}: {RED}{invalid_error}{Style.RESET_ALL}")
        return False
    
## Extracting js files 
def extract_js(url, page_content, custom_headers): 
    """Extract JavaScript files links from page source"""
    
    print(f"{Fore.YELLOW}[!]{RESET} Extracting JavaScript Files from {Fore.YELLOW}{url}{RESET}")

    js_file_pattern = r'src=["\']?([^"\'>\s]+\.js)(\?.*?)?["\'\s>]'
    js_files = re.findall(js_file_pattern, page_content)

    print(f"{GREEN}[+]{RESET} {len(js_files)} file(s) found\n")

    for js_file, _ in js_files: 
        if(js_file.startswith("http")):
            print(f"{Fore.YELLOW}[!]{RESET}Scanning {Fore.YELLOW}{js_file}{RESET}")
            scan(js_file, custom_headers)

        else : 
            final_url = f"{url}{js_file}"
            print(f"{Fore.YELLOW}[!]{RESET}Scanning {Fore.YELLOW}{final_url}{RESET}")

def banner(): 
    """Prints Banner"""

    print(rf"""{BOLD}{Fore.YELLOW}
         __o__     o__ __o                  o      o__ __o      o__ __o   
           |      /v     v\               _<|>_   /v     v\    /v     v\  
          / \    />       <\                     />       <\  />       <\ 
          \o/   _\o____        \o__ __o     o    \o           \o          
           |         \_\__o__   |     |>   <|>    |>_          |>_        
          < >              \   / \   / \   / \    |            |          
  \        |     \         /   \o/   \o/   \o/   <o>          <o>         
   o       o      o       o     |     |     |     |            |          
   <\__ __/>      <\__ __/>    / \   / \   / \   / \          / \         
                                                                          
                                                                          
                                                                          
Investigating JavaScript files since 2025
by mahaveer choudhary
{RESET}""")
    

if __name__ == "__main__":
    banner()

    parser = ArgumentParser()
    parser.add_argument("-u", "--url", help="Specify the target URL", required=True)
    parser.add_argument("-H", "--HEADER", help="Specify a custom header to be used", nargs=2, default=[], action='append')
    args = parser.parse_args()

    perform_check(args)