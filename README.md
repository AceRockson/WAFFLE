# WAFFLE

WAFFLE stands for Web Application Firewall For Limited Exploitation and is **a simple but powerful** WAF still under development that provides maximum security against common web threats like XSS Attacks,SQL Injections,Command Injections e.t.c. 

It also provides some extra security features that will be clearly analyzed in the documentation that will be provided in the next few weeks. 

**WAFFLE is currently tested with**

  * Commix
  * sqlmap
  * acunetix
 
**In**

  * Damn Vulnerable Web Application(DVWA)
  * Commix-testbed
  * Self Made Apps

**and prevented any possible threats.**

WAFFLE Differs from other Open Source WAFs, because it doesn't have a rule-set and does not end the script execution. It simply sanitizes any User Input and returns the data securely to your Application.

#### Advantages
  * User Friendly
  * Easy to configure
  * Easy to install
  * Fast in processing

#### Features / Protections Against

  * SQL Injection
  * XSS (Dom,reflected)
  * LFI/RFI
  * Command Injections
  * TOR Exit Nodes
  * Non Anonymous Proxies
  * Sensitive Files/Dirs with HTTP Authentication
  * CPU High Load (Load Average)
  * Max Input Limitations
  * Allowed Input Methods
  * Bad User agents
  * DDos
  * Brute Force Attacks
  * Force HTTPs Usage
  
### KNOWN ISSUES

  * php://input can't be filtered yet. You can however use $HTTP_RAW_POST_DATA in your Application safely
 
E-mail: acerockson@hotmail.com
 

### INSTALLATION

Simply Upload the waffle.php & config.ini in your preferable directory.

Open `php.ini`

Find 

`auto_prepend_file =`

Replace With

`auto_prepend_file = /your/directory/waffle.php`

<b>Restart Apache2 OR PHP-FPM and you are done!</b>
