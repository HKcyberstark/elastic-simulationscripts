## Prereqs

In order to run the tests, the test system should: 

* Have Python installed
  * RTAs were tested on python 3.11.4
  * No modules need to be installed.
* Modify the Execution policy:
  ```
  PowerShell.exe -ExecutionPolicy UnRestricted
  ```

## Ad Setup

The 'Audit Directory Service Changes' logging policy must be configured for (Success, Failure).
Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Changes (Success,Failure)
```

The 'Audit Directory Service Changes' logging policy must be configured for (Success, Failure).
Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Access (Success,Failure)
```

The 'Audit User Account Management' logging policy must be configured for (Success, Failure).
Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Account Management >
Audit User Account Management (Success,Failure)
```

## RTAs included:
  * `cert.py` - Needs admin privileges, executes a version of procmon with a revoked certificate
  * `odbcconf.py` - Didn't worked in the lab, included here because it still triggers the detection and was listed.
  * `uac_disable.py` - Needs admin privileges, temporarily disables uac related settings using registry.
  * `uac.py` - Perform various different uac bypasses. Should be executed with a non-admin user.
  * `wmi.py` - Needs admin privileges, creates an suspicious WMI event consumer.
  * `xsl.py` - Executes XSL scripts using WMIC and msxsl.
  * `group_enum.py` - Enumerates the members of the Domain Admins group.
  * `dcsyncprivs.py` - Modifies the ntSecurityDescriptor attribute to allow the test user to perform DCSync (also does the WRITEDACL Operation). Needs modification on `bin/dcsyncuser.ps1` with the target domain and accounts.

## Running the RTAs

* Using powershell, navigate to the `rta/` folder.
* Tests can be run with the following syntax:
    
    ```
    {python_executable} {rta_file}
    ```
    e.g.,
    ```
    py.exe .\cert.py
    ```