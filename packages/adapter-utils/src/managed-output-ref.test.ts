import { expect, it, vi } from "vitest";
import { managedOutputRef, parseManagedControlResult } from "./managed-ssh-handoff.js";
vi.mock("./server-utils.js", () => ({}));

it("binds a result to the protected admitted output directory and uid", () => {
  const expected = managedOutputRef(JSON.stringify({frame:{admitted_context:{business_command:{output_ref:{
    path:"/fixture/C-output",expected_uid:1000,expected_mode:0o700}}}}}));
  const binding = {operation_id:"operation-1",generation:1,context_digest:"a".repeat(64),payload_digest:"b".repeat(64)};
  const profile = {binding} as any;
  const owner = {instance_id:"12:34",...binding};
  const ref = {path:"/fixture/C-output/manifest.json",sha256:"c".repeat(64),size_bytes:20,
    media_type:"application/json",expected_uid:1000,expected_mode:0o600};
  const result = {schema:"homie.managed-control-result.v1",action:"status",binding,custody_status:"accepted",owner,
    status:"succeeded",cleanup_complete:true,error_code:null,result_ref:ref};
  expect(parseManagedControlResult(result,profile,"status",expected).result_ref).toEqual(ref);
  for (const malicious of [{...ref,path:"/fixture/C-output/secret-canary/manifest.json"},
    {...ref,path:"/secret-canary"},{...ref,expected_uid:1001}]) {
    expect(() => parseManagedControlResult({...result,result_ref:malicious},profile,"status",expected)).toThrow();
  }
  expect(() => parseManagedControlResult(result,profile,"status",null)).toThrow();
});
