import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import { authSessions, authUsers } from "./auth.js";

export const firebaseOperatorBindings = pgTable("firebase_operator_bindings", {
  id: uuid("id").primaryKey().defaultRandom(),
  projectId: text("project_id").notNull().default("thl-pclipd-api"),
  firebaseUid: text("firebase_uid").notNull(),
  userId: text("user_id").notNull().references(() => authUsers.id, { onDelete: "restrict" }),
  revision: integer("revision").notNull().default(1),
  enabled: boolean("enabled").notNull().default(true),
  createdByUserId: text("created_by_user_id").notNull().references(() => authUsers.id, { onDelete: "restrict" }),
  updatedByUserId: text("updated_by_user_id").notNull().references(() => authUsers.id, { onDelete: "restrict" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  identityUnique: uniqueIndex("firebase_operator_bindings_identity_uq").on(table.projectId, table.firebaseUid),
  enabledUserUnique: uniqueIndex("firebase_operator_bindings_enabled_user_uq").on(table.userId).where(sql`${table.enabled}`),
  revisionPositive: check("firebase_operator_bindings_revision_check", sql`${table.revision} > 0`),
  projectFixed: check("firebase_operator_bindings_project_check", sql`${table.projectId} = 'thl-pclipd-api'`),
  uidIndex: index("firebase_operator_bindings_user_idx").on(table.userId),
}));

export const firebaseOperatorSessionAssurance = pgTable("firebase_operator_session_assurance", {
  id: uuid("id").primaryKey().defaultRandom(),
  sessionId: text("session_id").notNull().unique().references(() => authSessions.id, { onDelete: "cascade" }),
  bindingId: uuid("binding_id").notNull().references(() => firebaseOperatorBindings.id, { onDelete: "restrict" }),
  userId: text("user_id").notNull().references(() => authUsers.id, { onDelete: "restrict" }),
  projectId: text("project_id").notNull().default("thl-pclipd-api"),
  firebaseUid: text("firebase_uid").notNull(),
  bindingRevision: integer("binding_revision").notNull(),
  authTimeSeconds: bigint("auth_time_seconds", { mode: "number" }).notNull(),
  totpFactors: jsonb("totp_factors").$type<Array<{ factorId: "totp"; uid: string }>>().notNull(),
  issuedAt: timestamp("issued_at", { withTimezone: true }).notNull(),
  lastAuthoritativeCheckAt: timestamp("last_authoritative_check_at", { withTimezone: true }).notNull(),
  lastInteractiveAt: timestamp("last_interactive_at", { withTimezone: true }).notNull(),
  absoluteExpiresAt: timestamp("absolute_expires_at", { withTimezone: true }).notNull(),
}, (table) => ({
  bindingIdx: index("firebase_operator_session_assurance_binding_idx").on(table.bindingId, table.bindingRevision),
  revisionPositive: check("firebase_operator_session_assurance_revision_check", sql`${table.bindingRevision} > 0`),
  projectFixed: check("firebase_operator_session_assurance_project_check", sql`${table.projectId} = 'thl-pclipd-api'`),
}));

export const firebaseOperatorProvisionPackets = pgTable("firebase_operator_provision_packets", {
  id: uuid("id").primaryKey().defaultRandom(),
  actorUserId: text("actor_user_id").notNull().references(() => authUsers.id, { onDelete: "restrict" }),
  intentHash: text("intent_hash").notNull(),
  intent: jsonb("intent").$type<Record<string, unknown>>().notNull(),
  expectedBindingState: jsonb("expected_binding_state").$type<Record<string, unknown> | null>(),
  expectedGrantStateHash: text("expected_grant_state_hash").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  status: text("status").notNull().default("pending"),
  appliedBindingId: uuid("applied_binding_id").references(() => firebaseOperatorBindings.id, { onDelete: "restrict" }),
  appliedBindingRevision: integer("applied_binding_revision"),
  createdMembershipIds: jsonb("created_membership_ids").$type<string[]>().notNull().default([]),
  createdGrantIds: jsonb("created_grant_ids").$type<string[]>().notNull().default([]),
  postGrantStateHash: text("post_grant_state_hash"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  actorIdx: index("firebase_operator_provision_packets_actor_idx").on(table.actorUserId, table.status),
  statusCheck: check("firebase_operator_provision_packets_status_check", sql`${table.status} in ('pending', 'applied', 'rolled_back', 'partial')`),
  hashCheck: check("firebase_operator_provision_packets_hash_check", sql`${table.intentHash} ~ '^[0-9a-f]{64}$' and ${table.expectedGrantStateHash} ~ '^[0-9a-f]{64}$'`),
}));

export const firebaseOperatorProvisionEvents = pgTable("firebase_operator_provision_events", {
  id: uuid("id").primaryKey().defaultRandom(),
  packetId: uuid("packet_id").notNull().references(() => firebaseOperatorProvisionPackets.id, { onDelete: "restrict" }),
  actorUserId: text("actor_user_id").notNull().references(() => authUsers.id, { onDelete: "restrict" }),
  action: text("action").notNull(),
  outcome: text("outcome").notNull(),
  details: jsonb("details").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  packetIdx: index("firebase_operator_provision_events_packet_idx").on(table.packetId, table.createdAt),
}));
