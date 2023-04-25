# enum_cvss

This Python script reads a list of components from a file, line by line and then uses the BD API to determine if that component has any vulnerabilities. If it does, it enumerates additional information including the CVSS 2 and CVSS 3 scores (the main reason FM wants the script). I used the same centralized logging facility for both error handling and saving the output to csv. I also tried to combine the initial authentication and pulling of data from the endpoints into the same function and just couldn’t get it to work. So instead, there’s an initial authentication function and a separate function that pulls data from the targeted endpoint.  

## Features
 - Provides ability to use a component list as input
 - Searches for vulnerabilities in the component and if found, shows CVSS 2 and CVSS 3 scores
 - Gives ability to save output to csv
 - Authenticates using a BD API key (redacted in the script) and then uses the Bearer Token for the duration of the session 
 - Quiet mode
 
### Usage

enum_cvss_v5.py {component name}
    Find cvss2 and cvss3 base scores for a given component.

Explanation:
    This script pulls component data from the BD API and if there are vulnerabilities, will display the CVSS 2.x and CVSS 3.x base scores.

Positional arguments:
    At the moment - none.

Optional arguments:
    Common Options:
    -h        --help    Print this help message
    -i        --info    Print authentication information
    -q        --quiet   Quiet mode
    -v        --version Version of this program
    -vv       --verbose Verbosity of output

Examples:
    python3 enum_cvss.py

#### Example:

python3 enum_cvss_v5.py -s

Quiet mode is [DISABLED]

Component name: ESAPI

Checking for vulnerabilities...
Vulnerability ID: CVE-2010-3300
CVSS 2 Base Score: 4.3
CVSS 3 Base Score: 5.9
Appending output to: enum_output.csv

Checking for vulnerabilities...
Vulnerability ID: BDSA-2022-1808
CVSS 2 Base Score: 4.6
CVSS 3 Base Score: 7.5
Appending output to: enum_output.csv

Checking for vulnerabilities...
Vulnerability ID: CVE-2022-24891
CVSS 2 Base Score: 4.3
CVSS 3 Base Score: 6.1
Appending output to: enum_output.csv

Checking for vulnerabilities...
Vulnerability ID: CVE-2022-23457
CVSS 2 Base Score: 7.5
CVSS 3 Base Score: 9.8
Appending output to: enum_output.csv

Checking for vulnerabilities...
Vulnerability ID: BDSA-2022-1809
CVSS 2 Base Score: 4.3
CVSS 3 Base Score: 6.1
Appending output to: enum_output.
