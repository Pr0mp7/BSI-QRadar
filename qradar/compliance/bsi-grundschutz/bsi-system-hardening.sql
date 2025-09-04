-- BSI IT-Grundschutz SYS.1.1 - System Hardening Verification
-- Requirement: Monitor system configuration changes per BSI Grundschutz
-- Last Updated: 2024-01-01
-- Compliance: BSI IT-Grundschutz SYS.1.1

SELECT
    hostname,
    eventname,
    username,
    sourceip,
    eventtime,
    magnitude,
    credibility,
    categoryname
FROM events
WHERE
    (eventname MATCHES '.*Policy.*Changed.*' OR
     eventname MATCHES '.*Configuration.*Modified.*' OR
     eventname MATCHES '.*Security.*Setting.*' OR
     eventname MATCHES '.*Audit.*Policy.*' OR
     eventname MATCHES '.*Registry.*Modified.*') AND
    eventtime > NOW() - INTERVAL '24' HOUR
ORDER BY eventtime DESC
LIMIT 1000;