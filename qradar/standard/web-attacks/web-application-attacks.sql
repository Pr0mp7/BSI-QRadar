-- Web Application Attack Detection
-- Use Case 7: Detect web application attacks (OWASP Top 10)
-- Last Updated: 2024-01-01
-- MITRE ATT&CK: T1190 - Exploit Public-Facing Application

SELECT
    sourceip as client_ip,
    hostname as target_host,
    uri_stem,
    uri_query,
    http_method,
    response_code,
    user_agent,
    eventtime,
    bytes_sent,
    bytes_received,
    CASE 
        WHEN uri_query MATCHES '.*UNION SELECT.*' THEN 'SQL Injection'
        WHEN uri_query MATCHES '.*<script>.*' THEN 'Cross-Site Scripting (XSS)'
        WHEN uri_query MATCHES '.*/\.\..*' THEN 'Path Traversal'
        WHEN uri_query MATCHES '.*exec\(.*' THEN 'Command Injection'
        WHEN uri_query MATCHES '.*eval\(.*' THEN 'Code Injection'
        WHEN uri_query MATCHES '.*cmd\.exe.*' THEN 'OS Command Injection'
        WHEN uri_query MATCHES '.*/bin/sh.*' THEN 'Shell Injection'
        WHEN uri_query MATCHES '.*DROP TABLE.*' THEN 'SQL DDL Attack'
        WHEN uri_query MATCHES '.*INSERT INTO.*' THEN 'SQL Data Manipulation'
        ELSE 'Other Web Attack Pattern'
    END as attack_type
FROM events
WHERE
    categoryname = 'Web Server' AND
    (uri_query MATCHES '.*UNION SELECT.*' OR
     uri_query MATCHES '.*<script>.*' OR
     uri_query MATCHES '.*/\.\..*' OR
     uri_query MATCHES '.*exec\(.*' OR
     uri_query MATCHES '.*eval\(.*' OR
     uri_query MATCHES '.*cmd\.exe.*' OR
     uri_query MATCHES '.*/bin/sh.*' OR
     uri_query MATCHES '.*DROP TABLE.*' OR
     uri_query MATCHES '.*INSERT INTO.*') AND
    eventtime > NOW() - INTERVAL '1' HOUR
ORDER BY eventtime DESC
LIMIT 1000;