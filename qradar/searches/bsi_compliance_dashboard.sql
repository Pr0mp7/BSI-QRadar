-- BSI Grundschutz Compliance Dashboard Query
-- Daily compliance monitoring and reporting
-- Author: Compliance Team
-- Created: 2024-01-01

-- SYS.1.1 Server Compliance Check
SELECT 
    'SYS.1.1 - Server Hardening' as Control,
    CASE 
        WHEN COUNT(*) = 0 THEN 'COMPLIANT'
        ELSE 'NON-COMPLIANT'
    END as Status,
    COUNT(*) as Violations,
    'Server configuration changes detected' as Description
FROM events 
WHERE 
    eventname MATCHES '.*Configuration.*Change.*' AND
    sourceip IN (SELECT ip FROM assets WHERE asset_type='QRadar') AND
    eventtime > NOW() - INTERVAL '24' HOUR

UNION ALL

-- NET.1.1 Network Security Check
SELECT 
    'NET.1.1 - Network Architecture' as Control,
    CASE 
        WHEN COUNT(*) = 0 THEN 'COMPLIANT'
        ELSE 'NON-COMPLIANT' 
    END as Status,
    COUNT(*) as Violations,
    'Unauthorized network access detected' as Description
FROM flows
WHERE
    (sourceip NOT LIKE '10.10.%' AND destinationip LIKE '10.10.%') AND
    eventtime > NOW() - INTERVAL '24' HOUR

UNION ALL

-- ORP.4 Identity Management Check
SELECT
    'ORP.4 - Identity Management' as Control,
    CASE
        WHEN COUNT(*) = 0 THEN 'COMPLIANT'
        ELSE 'NON-COMPLIANT'
    END as Status,
    COUNT(*) as Violations,
    'Failed authentication attempts from unauthorized sources' as Description
FROM events
WHERE
    eventname MATCHES '.*Failed.*Login.*' AND
    sourceip NOT IN (SELECT ip FROM authorized_admin_ips) AND
    eventtime > NOW() - INTERVAL '24' HOUR

ORDER BY 
    CASE Status
        WHEN 'NON-COMPLIANT' THEN 1
        ELSE 2
    END,
    Control