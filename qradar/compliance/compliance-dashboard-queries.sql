-- Compliance Dashboard Summary Queries
-- These queries support automated compliance reporting
-- Last Updated: 2024-01-01

-- Daily Compliance Summary Report
SELECT
    'PCI DSS' as regulation,
    COUNT(*) as violations,
    AVG(magnitude) as avg_severity,
    MAX(eventtime) as last_incident
FROM offenses
WHERE
    rules MATCHES '.*PCI.*' AND
    starttime > NOW() - INTERVAL '24' HOUR

UNION

SELECT
    'NIS2' as regulation,
    COUNT(*) as violations,
    AVG(magnitude) as avg_severity,
    MAX(eventtime) as last_incident
FROM offenses
WHERE
    rules MATCHES '.*NIS2.*' AND
    starttime > NOW() - INTERVAL '24' HOUR

UNION

SELECT
    'KRITIS' as regulation,
    COUNT(*) as violations,
    AVG(magnitude) as avg_severity,
    MAX(eventtime) as last_incident
FROM offenses
WHERE
    rules MATCHES '.*KRITIS.*' AND
    starttime > NOW() - INTERVAL '24' HOUR

UNION

SELECT
    'GDPR' as regulation,
    COUNT(*) as violations,
    AVG(magnitude) as avg_severity,
    MAX(eventtime) as last_incident
FROM offenses
WHERE
    rules MATCHES '.*GDPR.*' AND
    starttime > NOW() - INTERVAL '24' HOUR

UNION

SELECT
    'BSI Grundschutz' as regulation,
    COUNT(*) as violations,
    AVG(magnitude) as avg_severity,
    MAX(eventtime) as last_incident
FROM offenses
WHERE
    rules MATCHES '.*BSI.*' AND
    starttime > NOW() - INTERVAL '24' HOUR

ORDER BY violations DESC;