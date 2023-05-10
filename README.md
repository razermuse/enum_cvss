# enum_cvss

This Python script reads a list of components from a file, line by line and then uses the BD API to determine if that component has any vulnerabilities. If it does, it enumerates additional information including the CVSS 2 and CVSS 3 scores (the main reason FM wants the script). I used the same centralized logging facility for both error handling and saving the output to csv. I also tried to combine the initial authentication and pulling of data from the endpoints into the same function and just couldn’t get it to work. So instead, there’s an initial authentication function and a separate function that pulls data from the targeted endpoint.  

## Features
 - Provides ability to use a component list as input
 - Searches for vulnerabilities in the component and if found, shows CVSS 2 and CVSS 3 scores
 - Gives ability to save output to csv
 - Authenticates using a BD API key (redacted in the script) and then uses the Bearer Token for the duration of the session 
 - Quiet mode
 
### Usage

enum_cvss_v7.py
    Find CVSS 2.x and CVSS 3.x base scores for a given component.

Explanation:
    Pull component data via a list; if there are vulnerabilities: display CVSS 2 and CVSS 3 basescores.

Errors are logged to 'enum_cvss.log'.

Positional arguments:
    -s       --save      <filename> (optional)

Optional arguments:
    Common Options:
    -h        --help     Display this help message.
    -i        --info     Display base URL, authentication URL, API/Bearer/CSRF Tokens, and commands selected.
    -q        --quiet    Quiet mode.
    -s        --save     Save results. Will use 'enum_output.csv' if a filename isn't given.
    -vv       --verbose  Display (or save) vulnerability name, severity, description, HREF, and affected projects.
    -v        --version  Version of this program.

Examples:
    python3 enum_cvss.py -vv -s my_output.csv

#### Example:

python3 enum_cvss_v7.py -vv -s

Quiet mode is [DISABLED]

Component Name: esapi-java-legacy  Component Version: 2.1.0  Component ID: dc68ccd9-973d-48fa-aa87-f242807112f0
Medium: 3

Checking for vulnerabilities...
Vulnerability Name: BDSA-2022-1808 (Severity: MEDIUM)
Description: ESAPI is vulnerable to control-flow-bypass check failure due to an improper default implementation of the validator method `getValidDirectoryPath()`. This could be leveraged by an attacker to perform path traversal attacks that would normally be restricted by the validator.
CVSS 2 Basescore: 4.6 CVSS 3 Basescore: 7.5
HREF: https://poc09.blackduck.synopsys.com/api/vulnerabilities/BDSA-2022-1808
Affected Projects: Ticketbook_AskId_0068902_dev (0.9.1-SNAPSHOT)
Appending output to: enum_output.csv

Checking for vulnerabilities...
Vulnerability Name: BDSA-2022-1809 (Severity: MEDIUM)
Description: ESAPI is vulnerable to cross-site scripting (XSS) due to an improperly defined regular expression within the `antisamy-esapi.xml` configuration file. This could allow an attacker to supply malicious `javascript:` URIs, and steal sensitive information such as authentication tokens and user session cookies.
CVSS 2 Basescore: 4.3 CVSS 3 Basescore: 6.1
HREF: https://poc09.blackduck.synopsys.com/api/vulnerabilities/BDSA-2022-1809
Affected Projects: Ticketbook_AskId_0068902_dev (0.9.1-SNAPSHOT)
Appending output to: enum_output.csv

Checking for vulnerabilities...
Vulnerability Name: CVE-2022-24891 (Severity: MEDIUM)
Description: ESAPI (The OWASP Enterprise Security API) is a free, open source, web application security control library. Prior to version 2.3.0.0, there is a potential for a cross-site scripting vulnerability in ESAPI caused by a incorrect regular expression for "onsiteURL" in the **antisamy-esapi.xml** configuration file that can cause "javascript:" URLs to fail to be correctly sanitized. This issue is patched in ESAPI 2.3.0.0. As a workaround, manually edit the **antisamy-esapi.xml** configuration files to change the "onsiteURL" regular expression. More information about remediation of the vulnerability, including the workaround, is available in the maintainers' release notes and security bulletin.
CVSS 2 Basescore: 4.3 CVSS 3 Basescore: 6.1
HREF: https://poc09.blackduck.synopsys.com/api/vulnerabilities/CVE-2022-24891
