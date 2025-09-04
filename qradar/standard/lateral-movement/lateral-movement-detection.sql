-- Lateral Movement Detection
-- Use Case 5: Detect unauthorized movement within network
-- Last Updated: 2024-01-01
-- MITRE ATT&CK: T1021 - Remote Services

SELECT
    sourceip,
    COUNT(DISTINCT destinationip) as unique_destinations,
    COUNT(*) as total_connections,
    STRING_AGG(DISTINCT CAST(destinationport AS VARCHAR), ', ') as ports_used,
    MIN(eventtime) as first_connection,
    MAX(eventtime) as last_connection,
    AVG(CASE WHEN protocol = 'TCP' THEN 1 ELSE 0 END) * 100 as tcp_percentage
FROM flows
WHERE
    destinationport IN (22, 3389, 445, 135, 5985, 5986, 1433, 1521) AND
    protocol = 'TCP' AND
    eventtime > NOW() - INTERVAL '10' MINUTE
GROUP BY sourceip
HAVING COUNT(DISTINCT destinationip) > 5
ORDER BY unique_destinations DESC, total_connections DESC
LIMIT 500;