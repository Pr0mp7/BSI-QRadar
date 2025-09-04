-- NIS2 Article 20 - Supply Chain Security Monitoring
-- Requirement: Monitor third-party supplier access to critical systems
-- Last Updated: 2024-01-01
-- Compliance: NIS2 Directive Article 20

SELECT
    username,
    sourceip,
    destinationip,
    eventtime,
    eventname,
    hostname,
    COUNT(*) OVER (PARTITION BY username, sourceip) as access_count
FROM events
WHERE
    (username MATCHES '.*supplier_.*' OR
     username MATCHES '.*vendor_.*' OR
     username MATCHES '.*contractor_.*' OR
     username MATCHES '.*ext_.*' OR
     username MATCHES '.*external_.*') AND
    eventtime > NOW() - INTERVAL '24' HOUR
ORDER BY eventtime DESC
LIMIT 1000;