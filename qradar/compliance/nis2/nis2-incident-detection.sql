-- NIS2 Article 21 - Critical Infrastructure Incident Detection
-- Requirement: Detect cybersecurity incidents affecting critical infrastructure
-- Last Updated: 2024-01-01
-- Compliance: NIS2 Directive Article 21

SELECT
    sourceip,
    destinationip,
    eventname,
    eventtime,
    magnitude,
    credibility,
    categoryname,
    hostname
FROM events
WHERE
    magnitude >= 7 AND
    credibility >= 7 AND
    (categoryname MATCHES '.*Critical.*' OR 
     categoryname MATCHES '.*Infrastructure.*' OR
     categoryname MATCHES '.*Service.*Disruption.*' OR
     categoryname MATCHES '.*Operational.*Impact.*') AND
    eventtime > NOW() - INTERVAL '15' MINUTE
ORDER BY magnitude DESC, eventtime DESC
LIMIT 500;