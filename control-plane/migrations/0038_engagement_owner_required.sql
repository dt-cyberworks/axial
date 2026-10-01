-- Every engagement has an owner (REQ-IAM-021, GitHub issue #47, R3). REQ-IAM-007
-- always said "not null after migration"; the column stayed nullable, so legacy
-- engagements and the benchmark harness's engagements had none and were visible to
-- admins only. They are given to the oldest active administrator (an administrator
-- can reassign them), then the column is made NOT NULL.
--
-- Fail-closed: if ownerless engagements exist and there is no active administrator,
-- the migration stops with a clear error and changes nothing, instead of guessing
-- an owner. Idempotent: with no ownerless rows it only re-asserts NOT NULL.

DO $$
DECLARE
    ownerless  BIGINT;
    new_owner  UUID;
    owner_mail TEXT;
BEGIN
    SELECT count(*) INTO ownerless FROM engagement WHERE owner_user_id IS NULL;
    IF ownerless > 0 THEN
        SELECT id, email INTO new_owner, owner_mail
        FROM app_user
        WHERE role = 'admin' AND status = 'active'
        ORDER BY created_at, id
        LIMIT 1;
        IF new_owner IS NULL THEN
            RAISE EXCEPTION
                'cannot give % ownerless engagement(s) an owner: no active administrator exists. Create one (scripts/bootstrap_admin.py) and run the migration again.',
                ownerless;
        END IF;
        UPDATE engagement SET owner_user_id = new_owner WHERE owner_user_id IS NULL;
        RAISE NOTICE '% ownerless engagement(s) now belong to % (an administrator can reassign them)', ownerless, owner_mail;
    END IF;
END $$;

ALTER TABLE engagement ALTER COLUMN owner_user_id SET NOT NULL;
