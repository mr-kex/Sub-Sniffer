# Sub-Sniffer
Sub Sniffer is a versatile tool for subdomain enumeration that leverages various techniques and APIs to discover subdomains associated with a given domain. It supports multiple search engines, DNS queries, brute force enumeration, and API integrations to provide comprehensive results.

Features:
- Utilizes APIs from various sources including VirusTotal, Shodan, AlienVault, and more.
- Supports both passive and active subdomain enumeration techniques.
- Offers customizable options for wordlist-based brute force enumeration.

### Installation

➡ 1. Clone the repository:
```sh
git clone https://github.com/mr-kex/sub-sniffer.git
```
➡ 2. Navigate to the project directory:
```sh
cd sub-sniffer
```
➡ 3. Install dependencies using pip:
```sh
pip install -r requirements.txt
```
➡ 4. Run the tool:
```sh
python subsniffer.py -d example.com
```

### Usage:

Provide detailed instructions on how users can use your tool effectively. Include command-line options and examples. Here's a brief example:

 - To enumerate subdomains for a domain, use the following command:
```sh
      python subsniffer.py -d example.com
```
 - Options:

    -d, --domain: Specify the target domain to enumerate subdomains.
   
    -b, --bruteforce: Specify a custom wordlist file for brute force enumeration.
   
    -o, --output: Output subdomains to a text file.
   
    -v, --verbose: Enable verbose mode to display detailed output.
   
    -r, --recursive: Enable recursive subdomain enumeration.
   
    -t, --timeout: Set the timeout for HTTP requests (default: 30).

### Example Usage:

1. Enumerate subdomains for a domain using verbose mode:
```sh
    python subsniffer.py -d example.com -v
```
2. Perform recursive subdomain enumeration with a custom wordlist:
```sh
    python subsniffer.py -d example.com -r -b custom_wordlist.txt
```
3. Save subdomains to a text file:
```sh
    python subsniffer.py -d example.com -o output.txt
```

### License:

`sub-sniffer` is distributed under the MIT License. See [LICENSE](./LICENSE.md) for more information.

`sub-sniffer` is made with 🖤 by Mr. KEX [https://mrkex.blogspot.com] .
