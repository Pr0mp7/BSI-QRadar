-- ISO 27001 A.8.1 - Asset Management Monitoring
-- Requirement: Monitor access to information assets
-- Last Updated: 2024-01-01
-- Compliance: ISO 27001 A.8.1

SELECT
    username,
    sourceip,
    destinationip,
    hostname,
    eventtime,
    eventname,
    filename,
    COUNT(*) OVER (PARTITION BY username, hostname) as access_count
FROM events
WHERE
    (filename MATCHES '.*confidential.*' OR
     filename MATCHES '.*classified.*' OR
     filename MATCHES '.*restricted.*' OR
     filename MATCHES '.*sensitive.*' OR
     filename MATCHES '.*proprietary.*') AND
    eventtime > NOW() - INTERVAL '4' HOUR
ORDER BY eventtime DESC
LIMIT 1000;