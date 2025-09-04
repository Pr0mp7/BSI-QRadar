-- Data Exfiltration Detection
-- Use Case 4: Monitor for unusual data transfers
-- Last Updated: 2024-01-01
-- MITRE ATT&CK: T1041 - Exfiltration Over C2 Channel

SELECT
    sourceip,
    destinationip,
    SUM(bytessent) as total_bytes_sent,
    COUNT(*) as connection_count,
    AVG(bytessent) as avg_bytes_per_connection,
    MIN(eventtime) as first_connection,
    MAX(eventtime) as last_connection,
    COUNT(DISTINCT destinationport) as unique_ports
FROM flows
WHERE
    eventtime > NOW() - INTERVAL '5' MINUTE AND
    bytessent > 10485760  -- 10MB threshold
GROUP BY sourceip, destinationip
HAVING SUM(bytessent) > 52428800  -- 50MB total threshold
ORDER BY total_bytes_sent DESC
LIMIT 500;