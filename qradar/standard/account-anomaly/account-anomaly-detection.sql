-- Account Anomaly Detection
-- Use Case 9: Monitor for unusual account activities
-- Last Updated: 2024-01-01
-- MITRE ATT&CK: T1078 - Valid Accounts

SELECT
    username,
    sourceip,
    COUNT(*) as login_count,
    COUNT(DISTINCT sourceip) as unique_source_ips,
    COUNT(DISTINCT hostname) as unique_hosts_accessed,
    MIN(eventtime) as first_login,
    MAX(eventtime) as last_login,
    STRING_AGG(DISTINCT CAST(EXTRACT(HOUR FROM eventtime) AS VARCHAR), ', ') as login_hours,
    CASE 
        WHEN EXTRACT(HOUR FROM eventtime) BETWEEN 22 AND 6 THEN 'After Hours'
        WHEN EXTRACT(HOUR FROM eventtime) BETWEEN 7 AND 18 THEN 'Business Hours'
        ELSE 'Extended Hours'
    END as time_classification,
    CASE 
        WHEN COUNT(DISTINCT sourceip) > 5 THEN 'Multiple Source IPs'
        WHEN COUNT(*) > 50 THEN 'High Frequency Logins'
        WHEN EXTRACT(HOUR FROM eventtime) BETWEEN 22 AND 6 THEN 'After Hours Access'
        ELSE 'Normal Pattern'
    END as anomaly_type
FROM events
WHERE
    eventname = 'Authentication Successful' AND
    logon_type IN (2, 10) AND  -- Interactive and Remote Interactive
    eventtime > NOW() - INTERVAL '24' HOUR
GROUP BY username, sourceip, EXTRACT(HOUR FROM eventtime)
HAVING 
    COUNT(DISTINCT sourceip) > 3 OR
    COUNT(*) > 30 OR
    (EXTRACT(HOUR FROM eventtime) BETWEEN 22 AND 6 AND COUNT(*) > 5)
ORDER BY login_count DESC, unique_source_ips DESC
LIMIT 500;