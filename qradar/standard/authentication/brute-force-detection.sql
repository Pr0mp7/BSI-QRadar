-- Brute Force Authentication Attack Detection
-- Use Case 1: Multiple failed authentication attempts from same source
-- Last Updated: 2024-01-01
-- MITRE ATT&CK: T1110 - Brute Force

SELECT
    sourceip,
    username,
    COUNT(*) as failed_attempts,
    MIN(eventtime) as first_attempt,
    MAX(eventtime) as last_attempt,
    COUNT(DISTINCT hostname) as targeted_hosts
FROM events
WHERE
    eventname = 'Authentication Failed' AND
    eventtime > NOW() - INTERVAL '5' MINUTE
GROUP BY sourceip, username
HAVING COUNT(*) >= 5
ORDER BY failed_attempts DESC, last_attempt DESC
LIMIT 500;