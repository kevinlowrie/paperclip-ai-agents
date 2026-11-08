import { AsyncLocalStorage } from "node:async_hooks";

type Issuance = {
  userId: string;
  bindingId: string;
  bindingRevision: number;
  sessionTokenHash: string;
  consumed: boolean;
};

const issuance = new AsyncLocalStorage<Issuance>();

export async function withFirebaseOperatorSessionIssuance<T>(
  input: { userId: string; bindingId: string; bindingRevision: number; sessionTokenHash: string },
  operation: () => Promise<T>,
): Promise<T> {
  return issuance.run({ ...input, consumed: false }, operation);
}

export function consumeFirebaseOperatorSessionIssuance(input: {
  userId: string;
  actualSessionTokenHash: string;
}): { bindingId: string; bindingRevision: number } | null {
  const current = issuance.getStore();
  if (!current || current.consumed || current.userId !== input.userId || current.sessionTokenHash !== input.actualSessionTokenHash) return null;
  current.consumed = true;
  return { bindingId: current.bindingId, bindingRevision: current.bindingRevision };
}
