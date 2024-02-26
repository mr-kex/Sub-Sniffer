import requests
import dns.resolver
from bs4 import BeautifulSoup
import concurrent.futures
import json
import dns.zone
import re
from googlesearch import search
import urllib3
from colorama import Fore, Style
import argparse
import concurrent.futures

class SubdomainEnumerator:
    def __init__(self, domain, wordlist_file="./wordlist/brute_worlist.txt", verbose=False):
        self.domain = domain
        self.wordlist_file = wordlist_file
        self.subdomains = set()
        self.subscrt = []
        self.verbose = verbose


    def load_api_keys(self, filename="./API/api_keys.json"):
        try:
            with open(filename) as f:
                self.api_keys = json.load(f)
                self.virustotal_api_key = self.api_keys.get("virustotal_api_key")
                self.shodan_api_key = self.api_keys.get("shodan_api_key")
                self.censys_api_id = self.api_keys.get("censys_api_id")
                self.censys_api_secret = self.api_keys.get("censys_api_secret")
        except FileNotFoundError:
            self.api_keys = {}

    def extract_subdomain_from_url(self, url):
        match = re.search(r"(https?://)?((?:\w+\.)?(\w+\." + re.escape(self.domain) + r"))", url)
        if match:
            return match.group(2)
        return None

    def find_subdomains_duckduck(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using DuckDuckGo...{Style.RESET_ALL}")
            url = f"https://www.duckduckgo.com/html?q=site:{self.domain}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.130 Safari/537.3'
            }
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for result in soup.select('a.result__a'):
                    href = result.get('href')
                    subdomain = self.extract_subdomain_from_url(href)
                    if subdomain and subdomain not in self.subdomains:
                        self.subdomains.add(subdomain)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using DuckDuckGo.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in DuckDuckGo module: {e}{Style.RESET_ALL}")

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def find_subdomains_brute_force(self, num_threads=50):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Bruteforcing...{Style.RESET_ALL}")

            with open(self.wordlist_file, 'r') as file:
                wordlist = file.readlines()

            def check_subdomain(subdomain):
                url = f"http://{subdomain.strip()}.{self.domain}"
                if self.verbose:
                    print(f"Testing subdomain: {url}")
                try:
                    response = requests.get(url, timeout=5, verify=False)  
                    if response.status_code == 200:
                        self.subdomains.add(url)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Bruteforcing.{Style.RESET_ALL}")
                    else:
                        if self.verbose:
                            print(f"{Fore.RED}Subdomain {url} returned status code {response.status_code}.{Style.RESET_ALL}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}Error accessing {url}: {e}{Style.RESET_ALL}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                executor.map(check_subdomain, wordlist)

        except FileNotFoundError:
            print(f"{Fore.RED}Wordlist file {self.wordlist_file} not found.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in brute force module: {e}{Style.RESET_ALL}")

    def find_subdomains_crt_sh(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Crt...{Style.RESET_ALL}")
            url = f"https://crt.sh/?q=%25.{self.domain}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for td in soup.find_all('td'):
                    domain = td.text.strip()
                    if domain.endswith(self.domain):
                        subdomains = domain.split(self.domain)
                        for subdomain in subdomains:
                            if subdomain and subdomain not in self.subdomains:
                                full_subdomain = subdomain.strip() + self.domain
                                self.subscrt.append(full_subdomain)
                        
                self.subscrt.append(subdomain)
                
                self.subdomains.update(self.subscrt)
                if self.verbose:
                    print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Crt.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in crt.sh module: {e}{Style.RESET_ALL}")

    def find_subdomains_netcraft(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Netcraft...{Style.RESET_ALL}")
            url = f"https://searchdns.netcraft.com/?restriction=site+contains&host=*.{self.domain}&lookup=wait..&position=limited"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for td in soup.find_all('td'):
                    subdomain = td.text.strip()
                    if subdomain.startswith("www.") or subdomain.startswith("*"):
                        self.subdomains.add(subdomain[4:])
                    else:
                        self.subdomains.add(subdomain)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Netcraft.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in Netcraft module: {e}{Style.RESET_ALL}")

    def find_subdomains_shodan(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Shodan...{Style.RESET_ALL}")
            self.load_api_keys()
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
                "Authorization": f"Bearer {self.shodan_api_key}"
            }
            url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_api_key}&query=ssl:*.{self.domain}.*+200"
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()

                for result in data['matches']:
                    subdomain = result['hostnames'][0] if result['hostnames'] else result['domains'][0]
                    self.subdomains.add(subdomain)
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Shodan.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in Shodan module: {e}{Style.RESET_ALL}")

    def find_subdomains_censys(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Censys...{Style.RESET_ALL}")
            self.load_api_keys()
            url = f"https://censys.io/api/v1/search/ipv4"
            data = {
                "query": f"parsed.names: {self.domain}"
            }
            auth = (self.censys_api_id, self.censys_api_secret)
            response = requests.post(url, auth=auth, json=data)
            if response.status_code == 200:
                results = response.json()['results']
                for result in results:
                    self.subdomains.add(result['parsed.names'][0])
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Censys.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in Censys module: {e}{Style.RESET_ALL}")

    def find_subdomains_virustotal(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Virustotal...{Style.RESET_ALL}")
            self.load_api_keys()
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            headers = {
                "X-Apikey": self.virustotal_api_key
            }
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                for item in data['data']:
                    subdomain = item['id']
                    if subdomain not in self.subdomains:
                        self.subdomains.add(subdomain)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Virustotal.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in VirusTotal module: {e}{Style.RESET_ALL}")

    def find_subdomains_ask(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Ask...{Style.RESET_ALL}")
            url = f"http://www.ask.com/web?q=site:{self.domain}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    subdomain = self.extract_subdomain_from_url(href)
                    if subdomain and subdomain not in self.subdomains:
                        self.subdomains.add(subdomain)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Ask.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in Ask Search module: {e}{Style.RESET_ALL}")

    def find_subdomains_baidu(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Baidu...{Style.RESET_ALL}")
            url = f"https://www.baidu.com/s?wd=site:{self.domain}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    subdomain = self.extract_subdomain_from_url(href)
                    if subdomain and subdomain not in self.subdomains:
                        self.subdomains.add(subdomain)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Baidu.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in Baidu Search module: {e}{Style.RESET_ALL}")

    def find_subdomains_securitytrails(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Securitytrails...{Style.RESET_ALL}")
            url = f"https://securitytrails.com/list/apex_domain/{self.domain}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for td in soup.find_all('td', class_='formatted'):
                    subdomain = td.text.strip()
                    if subdomain.endswith(f'.{self.domain}'):
                        self.subdomains.add(subdomain)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Securitytrails.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in SecurityTrails module: {e}{Style.RESET_ALL}")
            
    def find_subdomains_sitedossier(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Sitedossier...{Style.RESET_ALL}")
            url = f"http://www.sitedossier.com/site/{self.domain}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')

                for a in soup.find_all('a', href=True):
                    href = a['href']

                    if '/site/' in href:

                        subdomain = href.split('/site/')[1].strip('/')
                        if subdomain.endswith(f'.{self.domain}'):
                            self.subdomains.add(subdomain)
                            if self.verbose:
                                print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Sitedossier.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in SiteDossier module: {e}{Style.RESET_ALL}")

    def find_subdomains_dnsdumpster(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Dnsdumpster...{Style.RESET_ALL}")
            url = f"https://dnsdumpster.com/"
            headers = {'User-Agent': 'Mozilla/5.0'}
            data = {'remoteHost': self.domain, 'submit': 'Search'}
            response = requests.post(url, data=data, headers=headers, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for td in soup.find_all('td', class_='col-md-4'):
                    subdomain = td.text.strip()
                    self.subdomains.add(subdomain)
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Dnsdumpster.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in DNSDumpster module: {e}{Style.RESET_ALL}")

    def find_subdomains_exalead(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Exalead...{Style.RESET_ALL}")
            url = f"https://www.exalead.com/search/web/results/?q=site%3A{self.domain}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for h3 in soup.find_all('h3', class_='ellip'):
                    subdomain = h3.text.strip()
                    if subdomain.endswith(f'.{self.domain}'):
                        self.subdomains.add(subdomain)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Exalead.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in Exalead module: {e}{Style.RESET_ALL}")

    def find_subdomains_google(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Google...{Style.RESET_ALL}")
            query = f"site:{self.domain}"
            for url in search(query, stop=20): 
                subdomain = self.extract_subdomain_from_url(url)
                if subdomain and subdomain.endswith(f'.{self.domain}') and subdomain not in self.subdomains:
                    self.subdomains.add(subdomain)
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Google.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"Error in Google module: {e}{Style.RESET_ALL}")

    def find_subdomains_bing(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Bing...{Style.RESET_ALL}")
            url = f"https://www.bing.com/search?q=site%3A{self.domain}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for cite in soup.find_all('cite'):
                    subdomain = self.extract_subdomain_from_url(cite.text)
                    if subdomain and subdomain not in self.subdomains:
                        self.subdomains.add(subdomain)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Bing.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in Bing module: {e}{Style.RESET_ALL}")

    def find_subdomains_ipv4info(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Ipv4info...{Style.RESET_ALL}")
            url = f"http://ipv4info.com/?hostname={self.domain}&submit=Submit"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                table = soup.find('table', class_='table-1')
                if table:
                    for td in table.find_all('td', class_='hostname'):
                        subdomain = td.text.strip()
                        if subdomain.endswith(f'.{self.domain}'):
                            self.subdomains.add(subdomain)
                            if self.verbose:
                                print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Ipv4info.{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError as ce:
            if self.verbose:
                print(f"{Fore.RED}Connection Error in IPV4info module: {ce}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in IPV4info module: {e}{Style.RESET_ALL}")

    def find_subdomains_yahoo(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Yahoo...{Style.RESET_ALL}")
            url = f"https://search.yahoo.com/search?p=site%3A{self.domain}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for h3 in soup.find_all('h3', class_='title'):
                    if h3.a:
                        subdomain = self.extract_subdomain_from_url(h3.a['href'])
                        if subdomain and subdomain not in self.subdomains:
                            self.subdomains.add(subdomain)
                            if self.verbose:
                                print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Yahoo.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in Yahoo module: {e}{Style.RESET_ALL}")

    def find_subdomains_alien_vault(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Alien...{Style.RESET_ALL}")
            alien_api_key = self.api_keys.get("alien_api_key")
            if alien_api_key:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
                headers = {'X-OTX-API-KEY': alien_api_key}
                response = requests.get(url, headers=headers, timeout=50)

                if response.status_code == 200:
                    data = response.json()
                    if 'passive_dns' in data:
                        for entry in data['passive_dns']:
                            hostname = entry['hostname']
                            if hostname not in self.subdomains:
                                self.subdomains.add(hostname)
                                if self.verbose:
                                    print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Alien.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error accessing AlienVault OTX API: {e}{Style.RESET_ALL}")

    def find_subdomains_binary_edge(self):
        try:
            if self.verbose:
                print(f"{Fore.YELLOW}[+] Searching for subdomains using Edge...{Style.RESET_ALL}")
            url = f"https://www.binaryedge.io/domains/{self.domain}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for subdomain in data['events']:
                    self.subdomains.add(subdomain['domain'])
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} subdomains using Edge.{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}Error in BinaryEdge module: {e}{Style.RESET_ALL}")

    def enumerate_subdomains(self):
        if self.verbose:
            print(f"{Fore.BLUE}=== Subdomain Enumeration Started ==={Style.RESET_ALL}")
        self.find_subdomains_duckduck()
        self.find_subdomains_crt_sh()
        self.find_subdomains_securitytrails()
        self.find_subdomains_netcraft()
        self.find_subdomains_sitedossier()
        self.find_subdomains_ask()
        self.find_subdomains_baidu()
        self.find_subdomains_exalead()
        self.find_subdomains_google()
        self.find_subdomains_bing()
        self.find_subdomains_ipv4info()
        self.find_subdomains_yahoo()
        self.find_subdomains_binary_edge()
        self.find_subdomains_shodan()
        self.find_subdomains_censys()
        self.find_subdomains_virustotal()
        self.find_subdomains_alien_vault()
        self.find_subdomains_brute_force()
        if self.verbose:
            print(f"{Fore.BLUE}=== Subdomain Enumeration Completed ==={Style.RESET_ALL}")

    def print_subdomains(self):
        print(f"{Fore.GREEN}Subdomains for {self.domain}:{Style.RESET_ALL}")
        for subdomain in self.subdomains:
            print(subdomain)

    def print_error(self, module_name, error):
        if self.verbose:
            print(f"{Fore.RED}Error in {module_name}: {error}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="Sub Sniffer - A tool for subdomain enumeration")
    parser.add_argument('-d', '--domain', required=True, help="Specify the domain to find subdomains")
    parser.add_argument('-b', '--bruteforce', help="Specify a custom wordlist file for brute force enumeration")
    parser.add_argument('-o', '--output', help="Output subdomains to a text file")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose mode")
    parser.add_argument('-r', '--recursive', action='store_true', help="Enable recursive subdomain enumeration")
    parser.add_argument('-t', '--timeout', type=int, default=30, help="Set the timeout for HTTP requests (default: 30)")
    parser.add_argument('-H', '--custom-help', action='help', default=argparse.SUPPRESS, help="Show this help message and exit")
    args = parser.parse_args()

    print(f"""{Fore.BLUE}
    ███████╗██╗   ██╗██████╗     ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
    ██╔════╝██║   ██║██╔══██╗    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
    ███████╗██║   ██║██████╔╝    ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
    ╚════██║██║   ██║██╔══██╗    ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
    ███████║╚██████╔╝██████╔╝    ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
    ╚══════╝ ╚═════╝ ╚═════╝     ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
                                                                                  
    {Style.RESET_ALL}""")

    enumerator = SubdomainEnumerator(args.domain)
    if args.bruteforce:
        enumerator.wordlist_file = args.bruteforce

    if args.verbose:
        enumerator.verbose = args.verbose

    enumerator.enumerate_subdomains()

    if args.output:
        with open(args.output, 'w') as f:
            for subdomain in enumerator.subdomains:
                f.write(subdomain + '\n')
        print(f"{Fore.GREEN}Subdomains saved to {args.output}{Style.RESET_ALL}")
    else:
        enumerator.print_subdomains()

if __name__ == "__main__":
    main()