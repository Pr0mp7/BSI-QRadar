-- GDPR Article 32 - Personal Data Access Monitoring
-- Requirement: Security of processing personal data
-- Last Updated: 2024-01-01
-- Compliance: GDPR Article 32

SELECT
    username,
    sourceip,
    table_name,
    operation,
    record_count,
    eventtime,
    database_name
FROM events
WHERE
    (table_name MATCHES '.*personal.*' OR 
     table_name MATCHES '.*customer.*' OR 
     table_name MATCHES '.*user.*' OR
     table_name MATCHES '.*employee.*' OR
     table_name MATCHES '.*gdpr.*' OR
     table_name MATCHES '.*privacy.*') AND
    eventtime > NOW() - INTERVAL '1' HOUR
ORDER BY eventtime DESC
LIMIT 1000;