# WAFFLE
WAFFLE stands for Web Application Firewall For Limited Exploitation and is an open source Web Application Firewall(WAF) that provides maximum security against common web threats like XSS Attacks,SQL Injections,Command Injections e.t.c. It also provides some extra security features that will be clearly analyzed in the documentation that will be provided in the next few weeks. WAFFLE is currently tested with sqlmap(for sql injections) and commix(for command injections) installed in a Damn Vulnerable Web Application(DVWA) and on a first approach the page can't be compromised at least with these two tools. I am still testing it though using the mentioned above tools and some other and the results will be available in the documentation for everyone to check. I built this for my final project though I encourage you to use it on your PHP pages for research purposes as long as for protection of your web apps as I think it's a very powerful tool. Below I am providing you with some installation steps but If you have any problems please feel free to contact me. If you have any suggestions or recommendations I'll leave you my contact information so that you can share them with me. And remember,it's a Limited Exploitation Firewall because as we know no system is safe.
 
E-mail: acerockson@hotmail.com
 

### INSTALLATION

Simply Upload the waffle.php in your preferable directory.

Open `php.ini`

Find 

`auto_prepend_file =`

Replace With

`auto_prepend_file = /your/directory/waffle.php`

<b>Restart Apache2 OR PHP-FPM and you are done!</b>
