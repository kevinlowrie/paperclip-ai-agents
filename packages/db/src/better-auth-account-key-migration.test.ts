import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import postgres from "postgres";
import { afterEach, describe, expect, it } from "vitest";
import { applyPendingMigrations } from "./client.js";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./test-embedded-postgres.js";

const MIGRATION_PREFIX = "0296_";
const cleanups: Array<() => Promise<void>> = [];
const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

async function migrationFile(): Promise<string> {
  const names = await fs.readdir(new URL("./migrations/", import.meta.url));
  const match = names.find((name) => name.startsWith(MIGRATION_PREFIX) && name.endsWith(".sql"));
  expect(match, `expected canonical ${MIGRATION_PREFIX} account-key migration`).toBeDefined();
  return match!;
}

async function migrationHash(file: string): Promise<string> {
  const content = await fs.readFile(new URL(`./migrations/${file}`, import.meta.url), "utf8");
  return createHash("sha256").update(content).digest("hex");
}

async function rewindMigration(sql: ReturnType<typeof postgres>, file: string): Promise<string> {
  const contentHash = await migrationHash(file);
  await sql`DELETE FROM drizzle.__drizzle_migrations WHERE hash = ${contentHash}`;
  return contentHash;
}

describeEmbeddedPostgres("Better Auth account key migration", () => {
  afterEach(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  });

  it("retains issuer history and allows distinct provider/account pairs", async () => {
    const database = await startEmbeddedPostgresTestDatabase("paperclip-account-key-");
    cleanups.push(database.cleanup);
    const sql = postgres(database.connectionString, { max: 1 });
    cleanups.push(async () => sql.end());
    const file = await migrationFile();
    await rewindMigration(sql, file);

    const userId = `user-${randomUUID()}`;
    await sql`
      INSERT INTO "user" (id, name, email, created_at, updated_at)
      VALUES (${userId}, 'Legacy', ${`${userId}@example.com`}, now(), now())
    `;
    const firstId = `account-${randomUUID()}`;
    const secondId = `account-${randomUUID()}`;
    await sql`
      INSERT INTO account (id, issuer, account_id, provider_id, user_id, password, created_at, updated_at)
      VALUES
        (${firstId}, 'local:credential', ${userId}, 'credential', ${userId}, 'legacy-password-hash', now(), now()),
        (${secondId}, 'local:oauth:github', 'github-subject-1', 'github', ${userId}, NULL, now(), now())
    `;

    await applyPendingMigrations(database.connectionString);

    const retained = await sql<{ id: string; issuer: string | null; password: string | null }[]>`
      SELECT id, issuer, password FROM account WHERE id IN (${firstId}, ${secondId}) ORDER BY id
    `;
    expect(retained).toHaveLength(2);
    expect(retained.find((row) => row.id === firstId)).toMatchObject({
      issuer: "local:credential",
      password: "legacy-password-hash",
    });

    const issuerColumn = await sql<{ is_nullable: string }[]>`
      SELECT is_nullable FROM information_schema.columns
      WHERE table_name = 'account' AND column_name = 'issuer'
    `;
    expect(issuerColumn[0]?.is_nullable).toBe("YES");

    const indexes = await sql<{ indexname: string }[]>`
      SELECT indexname FROM pg_indexes WHERE tablename = 'account'
    `;
    expect(indexes.map((row) => row.indexname)).not.toContain("account_issuer_account_id_uq");
    expect(indexes.map((row) => row.indexname)).toContain("account_provider_id_account_id_uq");

    await sql`
      INSERT INTO account (id, issuer, account_id, provider_id, user_id, created_at, updated_at)
      VALUES (${`account-${randomUUID()}`}, NULL, 'github-subject-2', 'github', ${userId}, now(), now()),
             (${`account-${randomUUID()}`}, NULL, ${userId}, 'github', ${userId}, now(), now())
    `;
  }, 30_000);

  it("fails closed on legacy key collisions and preserves schema and rows", async () => {
    const database = await startEmbeddedPostgresTestDatabase("paperclip-account-key-collision-");
    cleanups.push(database.cleanup);
    const sql = postgres(database.connectionString, { max: 1 });
    cleanups.push(async () => sql.end());
    const file = await migrationFile();
    const contentHash = await rewindMigration(sql, file);

    const userId = `user-${randomUUID()}`;
    await sql`
      INSERT INTO "user" (id, name, email, created_at, updated_at)
      VALUES (${userId}, 'Collision', ${`${userId}@example.com`}, now(), now())
    `;
    const accountIds = [`account-${randomUUID()}`, `account-${randomUUID()}`];
    await sql`
      INSERT INTO account (id, issuer, account_id, provider_id, user_id, created_at, updated_at)
      VALUES
        (${accountIds[0]}, 'legacy:issuer-a', 'same-subject', 'github', ${userId}, now(), now()),
        (${accountIds[1]}, 'legacy:issuer-b', 'same-subject', 'github', ${userId}, now(), now())
    `;

    let migrationError: unknown;
    try {
      await applyPendingMigrations(database.connectionString);
    } catch (error) {
      migrationError = error;
    }
    expect(migrationError).toBeInstanceOf(Error);
    expect(String(migrationError)).not.toContain(accountIds[0]);
    expect(String(migrationError)).not.toContain(accountIds[1]);
    expect(String(migrationError)).not.toContain(userId);

    const rows = await sql<{ id: string; issuer: string; account_id: string }[]>`
      SELECT id, issuer, account_id FROM account WHERE id IN (${accountIds[0]}, ${accountIds[1]}) ORDER BY id
    `;
    expect(rows).toHaveLength(2);
    expect(rows.map((row) => row.issuer)).toEqual(["legacy:issuer-a", "legacy:issuer-b"]);
    const issuerColumn = await sql<{ is_nullable: string }[]>`
      SELECT is_nullable FROM information_schema.columns
      WHERE table_name = 'account' AND column_name = 'issuer'
    `;
    expect(issuerColumn[0]?.is_nullable).toBe("NO");
    const oldIndex = await sql<{ indexname: string }[]>`
      SELECT indexname FROM pg_indexes WHERE tablename = 'account' AND indexname = 'account_issuer_account_id_uq'
    `;
    expect(oldIndex).toHaveLength(1);
    const migrationRecord = await sql<{ hash: string }[]>`
      SELECT hash FROM drizzle.__drizzle_migrations WHERE hash = ${contentHash}
    `;
    expect(migrationRecord).toHaveLength(0);
  }, 30_000);
});
