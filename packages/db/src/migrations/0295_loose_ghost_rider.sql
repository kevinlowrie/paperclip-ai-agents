CREATE TABLE "firebase_operator_bindings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"project_id" text DEFAULT 'thl-pclipd-api' NOT NULL,
	"firebase_uid" text NOT NULL,
	"user_id" text NOT NULL,
	"revision" integer DEFAULT 1 NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_by_user_id" text NOT NULL,
	"updated_by_user_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "firebase_operator_bindings_revision_check" CHECK ("firebase_operator_bindings"."revision" > 0),
	CONSTRAINT "firebase_operator_bindings_project_check" CHECK ("firebase_operator_bindings"."project_id" = 'thl-pclipd-api')
);
--> statement-breakpoint
CREATE TABLE "firebase_operator_provision_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"packet_id" uuid NOT NULL,
	"actor_user_id" text NOT NULL,
	"action" text NOT NULL,
	"outcome" text NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "firebase_operator_provision_packets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"actor_user_id" text NOT NULL,
	"intent_hash" text NOT NULL,
	"intent" jsonb NOT NULL,
	"expected_binding_state" jsonb,
	"expected_grant_state_hash" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"applied_binding_id" uuid,
	"applied_binding_revision" integer,
	"created_membership_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_grant_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"post_grant_state_hash" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "firebase_operator_provision_packets_status_check" CHECK ("firebase_operator_provision_packets"."status" in ('pending', 'applied', 'rolled_back', 'partial')),
	CONSTRAINT "firebase_operator_provision_packets_hash_check" CHECK ("firebase_operator_provision_packets"."intent_hash" ~ '^[0-9a-f]{64}$' and "firebase_operator_provision_packets"."expected_grant_state_hash" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
CREATE TABLE "firebase_operator_session_assurance" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"session_id" text NOT NULL,
	"binding_id" uuid NOT NULL,
	"user_id" text NOT NULL,
	"project_id" text DEFAULT 'thl-pclipd-api' NOT NULL,
	"firebase_uid" text NOT NULL,
	"binding_revision" integer NOT NULL,
	"auth_time_seconds" bigint NOT NULL,
	"totp_factors" jsonb NOT NULL,
	"issued_at" timestamp with time zone NOT NULL,
	"last_authoritative_check_at" timestamp with time zone NOT NULL,
	"last_interactive_at" timestamp with time zone NOT NULL,
	"absolute_expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "firebase_operator_session_assurance_session_id_unique" UNIQUE("session_id"),
	CONSTRAINT "firebase_operator_session_assurance_revision_check" CHECK ("firebase_operator_session_assurance"."binding_revision" > 0),
	CONSTRAINT "firebase_operator_session_assurance_project_check" CHECK ("firebase_operator_session_assurance"."project_id" = 'thl-pclipd-api')
);
--> statement-breakpoint
ALTER TABLE "firebase_operator_bindings" ADD CONSTRAINT "firebase_operator_bindings_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firebase_operator_bindings" ADD CONSTRAINT "firebase_operator_bindings_created_by_user_id_user_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firebase_operator_bindings" ADD CONSTRAINT "firebase_operator_bindings_updated_by_user_id_user_id_fk" FOREIGN KEY ("updated_by_user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firebase_operator_provision_events" ADD CONSTRAINT "firebase_operator_provision_events_packet_id_firebase_operator_provision_packets_id_fk" FOREIGN KEY ("packet_id") REFERENCES "public"."firebase_operator_provision_packets"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firebase_operator_provision_events" ADD CONSTRAINT "firebase_operator_provision_events_actor_user_id_user_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firebase_operator_provision_packets" ADD CONSTRAINT "firebase_operator_provision_packets_actor_user_id_user_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firebase_operator_provision_packets" ADD CONSTRAINT "firebase_operator_provision_packets_applied_binding_id_firebase_operator_bindings_id_fk" FOREIGN KEY ("applied_binding_id") REFERENCES "public"."firebase_operator_bindings"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firebase_operator_session_assurance" ADD CONSTRAINT "firebase_operator_session_assurance_session_id_session_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."session"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firebase_operator_session_assurance" ADD CONSTRAINT "firebase_operator_session_assurance_binding_id_firebase_operator_bindings_id_fk" FOREIGN KEY ("binding_id") REFERENCES "public"."firebase_operator_bindings"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firebase_operator_session_assurance" ADD CONSTRAINT "firebase_operator_session_assurance_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "firebase_operator_bindings_identity_uq" ON "firebase_operator_bindings" USING btree ("project_id","firebase_uid");--> statement-breakpoint
CREATE UNIQUE INDEX "firebase_operator_bindings_enabled_user_uq" ON "firebase_operator_bindings" USING btree ("user_id") WHERE "firebase_operator_bindings"."enabled";--> statement-breakpoint
CREATE INDEX "firebase_operator_bindings_user_idx" ON "firebase_operator_bindings" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "firebase_operator_provision_events_packet_idx" ON "firebase_operator_provision_events" USING btree ("packet_id","created_at");--> statement-breakpoint
CREATE INDEX "firebase_operator_provision_packets_actor_idx" ON "firebase_operator_provision_packets" USING btree ("actor_user_id","status");--> statement-breakpoint
CREATE INDEX "firebase_operator_session_assurance_binding_idx" ON "firebase_operator_session_assurance" USING btree ("binding_id","binding_revision");--> statement-breakpoint
CREATE FUNCTION reject_firebase_operator_provision_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'firebase operator provision events are append-only' USING ERRCODE = '42501';
END;
$$;--> statement-breakpoint
CREATE TRIGGER firebase_operator_provision_events_no_update_delete
BEFORE UPDATE OR DELETE ON firebase_operator_provision_events
FOR EACH ROW EXECUTE FUNCTION reject_firebase_operator_provision_event_mutation();--> statement-breakpoint
CREATE TRIGGER firebase_operator_provision_events_no_truncate
BEFORE TRUNCATE ON firebase_operator_provision_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_firebase_operator_provision_event_mutation();
