-- Brute Force Authentication Detection Rule
-- Use Case: Detect multiple failed authentication attempts
-- Author: Security Operations Team
-- Created: 2024-01-01

SELECT
    sourceip,
    username,
    COUNT(*) as failed_attempts,
    MIN(devicetime) as first_attempt,
    MAX(devicetime) as last_attempt
FROM events
WHERE
    eventname = 'Authentication Failed' AND
    eventtime > NOW() - INTERVAL '5' MINUTE
GROUP BY sourceip, username
HAVING COUNT(*) >= 5
ORDER BY failed_attempts DESC