-- ISO 27001 A.16.1 - Information Security Incident Management
-- Requirement: Detect and manage information security incidents
-- Last Updated: 2024-01-01
-- Compliance: ISO 27001 A.16.1

SELECT
    sourceip,
    destinationip,
    eventname,
    eventtime,
    magnitude,
    credibility,
    categoryname,
    hostname,
    username,
    CASE 
        WHEN magnitude >= 8 THEN 'Critical Incident'
        WHEN magnitude >= 6 THEN 'High Priority Incident'
        WHEN magnitude >= 4 THEN 'Medium Priority Incident'
        ELSE 'Low Priority Incident'
    END as incident_priority
FROM events
WHERE
    (categoryname MATCHES '.*Security.*Violation.*' OR
     categoryname MATCHES '.*Unauthorized.*Access.*' OR
     categoryname MATCHES '.*Malware.*Detection.*' OR
     categoryname MATCHES '.*Data.*Breach.*' OR
     categoryname MATCHES '.*Policy.*Violation.*') AND
    magnitude >= 4 AND
    credibility >= 5 AND
    eventtime > NOW() - INTERVAL '1' HOUR
ORDER BY magnitude DESC, eventtime DESC
LIMIT 500;