CREATE TABLE "firebase_operator_login_transactions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"origin" text NOT NULL,
	"company_id" uuid NOT NULL,
	"return_path" text NOT NULL,
	"browser_binding_hash" text NOT NULL,
	"csrf_state_hash" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	CONSTRAINT "firebase_operator_login_transactions_expiry_check" CHECK ("firebase_operator_login_transactions"."expires_at" > "firebase_operator_login_transactions"."created_at" and "firebase_operator_login_transactions"."expires_at" <= "firebase_operator_login_transactions"."created_at" + interval '300 seconds'),
	CONSTRAINT "firebase_operator_login_transactions_hashes_check" CHECK ("firebase_operator_login_transactions"."browser_binding_hash" ~ '^[0-9a-f]{64}$' and "firebase_operator_login_transactions"."csrf_state_hash" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "firebase_operator_login_transactions" ADD CONSTRAINT "firebase_operator_login_transactions_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "firebase_operator_login_transactions_expiry_idx" ON "firebase_operator_login_transactions" USING btree ("expires_at");