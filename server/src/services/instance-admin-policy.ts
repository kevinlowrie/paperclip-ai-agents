import { and, eq, sql } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { firebaseOperatorBindings, firebaseOperatorSessionAssurance, instanceUserRoles } from "@paperclipai/db";

type QueryDb = Pick<Db, "select">;

/**
 * DB-backed instance-admin authority is reserved for users with no Firebase
 * operator identity or assured operator session. All three facts are read in
 * one SQL statement so a binding cannot race a separate role lookup.
 */
export async function isEligibleInstanceAdmin(db: QueryDb, userId: string): Promise<boolean> {
  const row = await db.select({ id: instanceUserRoles.id })
    .from(instanceUserRoles)
    .where(and(
      eq(instanceUserRoles.userId, userId),
      eq(instanceUserRoles.role, "instance_admin"),
      sql`NOT EXISTS (
        SELECT 1 FROM ${firebaseOperatorBindings}
        WHERE ${firebaseOperatorBindings.userId} = ${instanceUserRoles.userId}
      )`,
      sql`NOT EXISTS (
        SELECT 1 FROM ${firebaseOperatorSessionAssurance}
        WHERE ${firebaseOperatorSessionAssurance.userId} = ${instanceUserRoles.userId}
      )`,
    ))
    .limit(1)
    .then((rows) => rows[0] ?? null);
  return Boolean(row);
}
