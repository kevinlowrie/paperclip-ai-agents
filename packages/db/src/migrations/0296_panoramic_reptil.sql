-- The account table is small identity state; lock out concurrent inserts/updates
-- so the preflight result remains valid through the unique-index creation.
LOCK TABLE "account" IN SHARE ROW EXCLUSIVE MODE;--> statement-breakpoint
DO $migration$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM "account"
    GROUP BY "provider_id", "account_id"
    HAVING COUNT(*) > 1
  ) THEN
    RAISE EXCEPTION 'Cannot upgrade authentication with ambiguous provider account identities.'
      USING ERRCODE = '23505';
  END IF;
END;
$migration$;--> statement-breakpoint
DROP INDEX "account_issuer_account_id_uq";--> statement-breakpoint
ALTER TABLE "account" ALTER COLUMN "issuer" DROP NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "account_provider_id_account_id_uq" ON "account" USING btree ("provider_id","account_id");