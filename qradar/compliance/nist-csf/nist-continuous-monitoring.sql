-- NIST CSF DE.CM - Security Continuous Monitoring
-- Requirement: Implement continuous monitoring capabilities
-- Last Updated: 2024-01-01
-- Compliance: NIST CSF Detect Function DE.CM

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
        WHEN magnitude >= 7 AND credibility >= 8 THEN 'Critical Anomaly'
        WHEN magnitude >= 5 AND credibility >= 6 THEN 'Significant Anomaly'
        WHEN magnitude >= 3 AND credibility >= 4 THEN 'Minor Anomaly'
        ELSE 'Baseline Activity'
    END as anomaly_level
FROM events
WHERE
    (categoryname MATCHES '.*Network.*Monitoring.*' OR
     categoryname MATCHES '.*Host.*Monitoring.*' OR
     categoryname MATCHES '.*Application.*Monitoring.*' OR
     categoryname MATCHES '.*Security.*Monitoring.*') AND
    eventtime > NOW() - INTERVAL '30' MINUTE
ORDER BY magnitude DESC, credibility DESC, eventtime DESC
LIMIT 1000;