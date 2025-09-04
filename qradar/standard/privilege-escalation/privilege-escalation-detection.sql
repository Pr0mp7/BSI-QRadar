-- Privilege Escalation Detection
-- Use Case 2: Unauthorized attempts to escalate privileges
-- Last Updated: 2024-01-01
-- MITRE ATT&CK: T1068, T1078 - Privilege Escalation

SELECT
    username,
    sourceip,
    destinationip,
    eventname,
    eventtime,
    magnitude,
    credibility,
    hostname,
    CASE 
        WHEN eventname MATCHES '.*Privilege.*Assigned.*' THEN 'Privilege Assignment'
        WHEN eventname MATCHES '.*Administrator.*Added.*' THEN 'Admin Rights Grant'
        WHEN eventname MATCHES '.*Elevation.*' THEN 'Token Elevation'
        WHEN eventname MATCHES '.*sudo.*' THEN 'Linux Sudo Usage'
        ELSE 'Other Privilege Event'
    END as escalation_type
FROM events
WHERE
    (eventname MATCHES '.*Privilege.*' OR
     eventname MATCHES '.*Administrator.*' OR
     eventname MATCHES '.*Elevation.*' OR
     eventname MATCHES '.*sudo.*' OR
     eventname MATCHES '.*runas.*') AND
    eventtime > NOW() - INTERVAL '1' HOUR
ORDER BY eventtime DESC
LIMIT 1000;