-- Network Scanning Detection
-- Use Case 10: Detect network reconnaissance activities
-- Last Updated: 2024-01-01
-- MITRE ATT&CK: T1046 - Network Service Scanning

SELECT
    sourceip,
    COUNT(DISTINCT destinationport) as unique_ports_scanned,
    COUNT(DISTINCT destinationip) as unique_hosts_scanned,
    COUNT(*) as total_attempts,
    MIN(eventtime) as scan_start,
    MAX(eventtime) as scan_end,
    STRING_AGG(DISTINCT CAST(destinationport AS VARCHAR), ', ') as ports_scanned,
    AVG(CASE WHEN action = 'ACCEPT' THEN 1 ELSE 0 END) * 100 as success_rate,
    CASE 
        WHEN COUNT(DISTINCT destinationport) > 100 THEN 'Port Sweep'
        WHEN COUNT(DISTINCT destinationip) > 50 THEN 'Network Sweep'
        WHEN COUNT(DISTINCT destinationport) > 20 AND COUNT(DISTINCT destinationip) > 10 THEN 'Combined Scan'
        ELSE 'Targeted Scan'
    END as scan_type
FROM flows
WHERE
    protocol = 'TCP' AND
    (
        action = 'BLOCK' OR 
        action = 'DENY' OR
        action = 'DROP'
    ) AND
    eventtime > NOW() - INTERVAL '2' MINUTE
GROUP BY sourceip
HAVING COUNT(DISTINCT destinationport) > 20
ORDER BY unique_ports_scanned DESC, unique_hosts_scanned DESC
LIMIT 500;