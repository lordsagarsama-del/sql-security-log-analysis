# SQL Security Log Analysis & Threat Investigation

## 📌 Project Overview
In this project, I investigated a potential security incident by analyzing organizational database records for suspicious authentication behavior[cite: 13]. Using MariaDB SQL syntax, I executed targeted filtering queries across login logs and employee directories to identify security vulnerabilities, track after-hours access attempts, and audit device access[cite: 13, 14, 17, 19].

## 🛠️ Tools & Environment
* **Database Management System:** MariaDB / MySQL
* **Language:** SQL (Structured Query Language)

## 🔍 Key Investigations & SQL Queries Executed

### 1. Investigating After-Hours Failed Login Attempts
To detect potential brute-force or unauthorized after-hours authentication attempts, I filtered `log_in_attempts` for failed logins (`success = false`) occurring after 18:00[cite: 13, 14]:
\`\`\`sql
SELECT * 
FROM log_in_attempts 
WHERE login_time > '18:00:00' AND success = false;
\`\`\`

### 2. Analyzing Specific Incident Date Windows
Following an anomaly detected on May 9, 2022, I expanded the query window to include the previous 24 hours to analyze potential reconnaissance traffic[cite: 14]:
\`\`\`sql
SELECT * 
FROM log_in_attempts 
WHERE login_date = '2022-05-09' OR login_date = '2022-05-08';
\`\`\`

### 3. Isolating International Network Traffic
Threat intelligence indicated malicious activity originated outside Mexican office locations[cite: 15]. To account for formatting discrepancies in the dataset (`MEX` and `MEX1CO`), I used `NOT` combined with `LIKE` wildcards to filter out all Mexican office variations[cite: 15, 16]:
\`\`\`sql
SELECT * 
FROM log_in_attempts 
WHERE NOT country LIKE 'MEX%';
\`\`\`

### 4. Auditing Department Workstations for Updates
To prepare hardware and software patch deployments across corporate divisions, I queried employee directory records for specific departments (e.g., Marketing personnel in the East building, Finance/Sales personnel, and non-IT teams)[cite: 17, 18, 19]:
\`\`\`sql
SELECT * 
FROM employees 
WHERE department = 'Marketing' AND office LIKE 'East%';
\`\`\`

## 🚀 Business Impact
By mastering structured SQL query filters (`WHERE`, `AND`, `OR`, `NOT`, `LIKE`), I demonstrated how to audit authentication telemetry, triage security incidents efficiently, and isolate vulnerable organizational assets with minimal latency[cite: 13, 15, 19, 20].
