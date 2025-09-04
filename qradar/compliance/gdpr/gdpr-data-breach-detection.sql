-- GDPR Data Breach Detection Query
-- Requirement: Detect potential personal data breaches
-- Last Updated: 2024-01-01
-- Compliance: GDPR Article 33 & 34

SELECT
    username,
    sourceip,
    table_name,
    operation,
    record_count,
    eventtime,
    database_name,
    CASE 
        WHEN operation = 'SELECT' AND record_count > 1000 THEN 'High Risk - Mass Data Access'
        WHEN operation IN ('UPDATE', 'DELETE') AND record_count > 100 THEN 'High Risk - Mass Data Modification'
        WHEN operation = 'DROP' THEN 'Critical Risk - Data Destruction'
        ELSE 'Medium Risk'
    END as breach_risk_level
FROM events
WHERE
    (table_name MATCHES '.*personal.*' OR 
     table_name MATCHES '.*customer.*' OR 
     table_name MATCHES '.*user.*') AND
    (
        (operation = 'SELECT' AND record_count > 1000) OR
        (operation IN ('UPDATE', 'DELETE') AND record_count > 100) OR
        (operation = 'DROP')
    ) AND
    eventtime > NOW() - INTERVAL '1' HOUR
ORDER BY record_count DESC, eventtime DESC
LIMIT 500;