-- DNS Tunneling Detection
-- Use Case 8: Identify DNS tunneling for data exfiltration or C2
-- Last Updated: 2024-01-01
-- MITRE ATT&CK: T1071.004 - Application Layer Protocol: DNS

SELECT
    sourceip,
    query_name,
    query_type,
    LENGTH(query_name) as query_length,
    COUNT(*) as query_count,
    MIN(eventtime) as first_query,
    MAX(eventtime) as last_query,
    AVG(LENGTH(query_name)) as avg_query_length,
    COUNT(DISTINCT query_type) as unique_query_types,
    CASE 
        WHEN LENGTH(query_name) >= 50 AND query_type = 'TXT' THEN 'Long TXT Query'
        WHEN LENGTH(query_name) >= 30 AND query_type = 'NULL' THEN 'Long NULL Query'
        WHEN LENGTH(query_name) >= 40 AND query_type = 'CNAME' THEN 'Long CNAME Query'
        WHEN query_name MATCHES '.*[0-9a-f]{32,}.*' THEN 'Hex Encoded Data'
        WHEN query_name MATCHES '.*[A-Za-z0-9+/]{20,}.*' THEN 'Base64 Encoded Data'
        ELSE 'Potential Tunneling'
    END as tunneling_indicator
FROM events
WHERE
    categoryname = 'DNS' AND
    (LENGTH(query_name) >= 50 OR
     query_type IN ('TXT', 'NULL', 'CNAME')) AND
    eventtime > NOW() - INTERVAL '5' MINUTE
GROUP BY sourceip, query_name, query_type
HAVING COUNT(*) > 10 OR AVG(LENGTH(query_name)) > 40
ORDER BY query_count DESC, avg_query_length DESC
LIMIT 500;