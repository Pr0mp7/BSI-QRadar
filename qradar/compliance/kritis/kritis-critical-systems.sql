-- KRITIS - Critical Infrastructure Protection Monitoring
-- Requirement: BSI-KRITIS-V - IT security for critical infrastructures
-- Last Updated: 2024-01-01
-- Compliance: KRITIS Regulation

SELECT
    sourceip,
    destinationip,
    eventname,
    eventtime,
    magnitude,
    credibility,
    hostname,
    categoryname
FROM events
WHERE
    (hostname MATCHES '.*scada.*' OR
     hostname MATCHES '.*ics.*' OR
     hostname MATCHES '.*critical.*' OR
     hostname MATCHES '.*control.*' OR
     hostname MATCHES '.*power.*' OR
     hostname MATCHES '.*water.*' OR
     hostname MATCHES '.*transport.*') AND
    magnitude >= 6 AND
    eventtime > NOW() - INTERVAL '1' HOUR
ORDER BY magnitude DESC, eventtime DESC
LIMIT 500;