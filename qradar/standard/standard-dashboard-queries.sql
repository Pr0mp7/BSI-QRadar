-- Standard Use Case Dashboard Queries
-- These queries support the main security monitoring dashboard
-- Last Updated: 2024-01-01

-- Top Security Events by Category (Last 24 Hours)
SELECT
    categoryname,
    COUNT(*) as event_count,
    AVG(magnitude) as avg_severity,
    COUNT(DISTINCT sourceip) as unique_sources,
    MAX(eventtime) as latest_event
FROM events
WHERE
    eventtime > NOW() - INTERVAL '24' HOUR AND
    magnitude >= 5
GROUP BY categoryname
ORDER BY event_count DESC
LIMIT 20;

-- Active Offenses Summary
SELECT
    offense_type,
    status,
    COUNT(*) as offense_count,
    AVG(magnitude) as avg_magnitude,
    MIN(start_time) as oldest_offense,
    MAX(start_time) as newest_offense
FROM offenses
WHERE
    status IN ('OPEN', 'PROTECTED')
GROUP BY offense_type, status
ORDER BY offense_count DESC;

-- Top Source IPs by Risk
SELECT
    sourceip,
    COUNT(*) as total_events,
    COUNT(DISTINCT categoryname) as event_categories,
    AVG(magnitude) as avg_severity,
    SUM(CASE WHEN magnitude >= 7 THEN 1 ELSE 0 END) as high_severity_events,
    MAX(eventtime) as last_activity
FROM events
WHERE
    eventtime > NOW() - INTERVAL '24' HOUR AND
    magnitude >= 3
GROUP BY sourceip
ORDER BY high_severity_events DESC, avg_severity DESC
LIMIT 50;