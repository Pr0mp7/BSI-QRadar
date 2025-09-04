-- PCI DSS 10.2 - Cardholder Data Access Monitoring
-- Requirement: Monitor all access to cardholder data
-- Last Updated: 2024-01-01
-- Compliance: PCI DSS 10.2.1

SELECT
    username,
    sourceip,
    destinationip,
    filename,
    eventtime,
    eventname,
    magnitude,
    credibility
FROM events
WHERE
    (eventname MATCHES '.*File.*Access.*' OR eventname MATCHES '.*Object.*Access.*') AND
    (filename MATCHES '.*cardholder.*' OR 
     filename MATCHES '.*payment.*' OR 
     filename MATCHES '.*card.*' OR
     filename MATCHES '.*PCI.*' OR
     filename MATCHES '.*CDE.*') AND
    eventtime > NOW() - INTERVAL '1' HOUR
ORDER BY eventtime DESC
LIMIT 1000;