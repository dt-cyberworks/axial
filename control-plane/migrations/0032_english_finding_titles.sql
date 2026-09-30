-- REQ-TEXT-001: finding titles the scanner used to write in German, renamed to
-- the English titles it writes now. Only the title changes: fingerprints stay
-- as they are, and app/api/internal.py maps the English titles back to the
-- original wording when fingerprinting, so re-scans keep matching these rows
-- and their triage decisions. Idempotent (each statement only matches the old
-- German wording). The hash-chained audit log is deliberately not touched.
UPDATE finding SET title = 'Missing security headers: ' || substr(title, length('Fehlende Security-Header: ') + 1)
 WHERE title LIKE 'Fehlende Security-Header: %';
UPDATE finding SET title = 'WAF detected: ' || substr(title, length('WAF erkannt: ') + 1)
 WHERE title LIKE 'WAF erkannt: %';
UPDATE finding SET title = 'OpenSSH - outdated version' WHERE title = 'OpenSSH - veraltete Version';
UPDATE finding SET title = 'Apache Tomcat - outdated version' WHERE title = 'Apache Tomcat - veraltete Version';
UPDATE finding SET title = 'MySQL - authentication bypass on repeated login'
 WHERE title = 'MySQL - Authentication Bypass bei wiederholtem Login';
