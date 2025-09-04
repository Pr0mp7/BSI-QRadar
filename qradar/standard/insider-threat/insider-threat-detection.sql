-- Insider Threat Detection
-- Use Case 6: Monitor suspicious activities by internal users
-- Last Updated: 2024-01-01
-- MITRE ATT&CK: T1005 - Data from Local System

SELECT
    username,
    sourceip,
    COUNT(*) as file_access_count,
    COUNT(DISTINCT filename) as unique_files_accessed,
    STRING_AGG(DISTINCT filename, ' | ') as accessed_files,
    MIN(eventtime) as first_access,
    MAX(eventtime) as last_access,
    COUNT(DISTINCT hostname) as systems_accessed
FROM events
WHERE
    eventname IN ('File Access', 'Object Access', 'Handle to Object Requested') AND
    (filename MATCHES '.*[Cc]onfidential.*' OR
     filename MATCHES '.*[Ss]ecret.*' OR
     filename MATCHES '.*[Pp]ersonal.*' OR
     filename MATCHES '.*[Rr]estricted.*' OR
     filename MATCHES '.*[Ii]nternal.*' OR
     filename MATCHES '.*[Pp]roprietary.*') AND
    eventtime > NOW() - INTERVAL '1' HOUR
GROUP BY username, sourceip
HAVING COUNT(*) >= 50
ORDER BY file_access_count DESC, unique_files_accessed DESC
LIMIT 500;