import { afterEach, expect, it, vi } from "vitest";
import fs from "node:fs/promises"; import os from "node:os"; import path from "node:path";
import {createHash} from "node:crypto"; import {execFileSync} from "node:child_process";
import {stageManagedCommand, managedCommandPath} from "./managed-command.js";
const roots:string[]=[];
afterEach(async()=>{vi.restoreAllMocks();for(const r of roots.splice(0))await fs.rm(r,{recursive:true,force:true});});
async function fixture(){
 const root=await fs.mkdtemp(path.join(os.tmpdir(),"managed-command-test-"));roots.push(root);
 const source=path.join(root,"operator");await fs.mkdir(source);
 const files={"wrapper.mjs":"#!/usr/bin/env node\nimport {message} from './bridge.mjs'; console.log(message);\n","bridge.mjs":"export const message='staged sibling works';\n"};
 for(const [p,s] of Object.entries(files))await fs.writeFile(path.join(source,p),s);
 return {root,source,config:{sourceDir:source,entrypoint:"wrapper.mjs",files:Object.entries(files).map(([p,s])=>({path:p,sha256:createHash("sha256").update(s).digest("hex")}))}};
}
it("stages pinned command plus sibling independently of selected workspace",async()=>{
 const f=await fixture();await fs.writeFile(path.join(f.source,"private.env"),"never copy");
 const staged=await stageManagedCommand(f.config);roots.push(staged.directory);
 const project=path.join(f.root,"selected-project");await fs.mkdir(project);
 const remote=path.join(f.root,"remote-command");await fs.cp(staged.directory,remote,{recursive:true});
 expect((await fs.readdir(remote)).sort()).toEqual(["bridge.mjs","wrapper.mjs"]);
 const command=managedCommandPath(staged,remote);
 expect(execFileSync(command,[],{cwd:project,encoding:"utf8"}).trim()).toBe("staged sibling works");
 await fs.writeFile(path.join(f.source,"bridge.mjs"),"changed after snapshot");
 expect(execFileSync(command,[],{cwd:project,encoding:"utf8"}).trim()).toBe("staged sibling works");
 expect(()=>managedCommandPath(staged,undefined)).toThrow();
});
it("rejects digest drift",async()=>{const f=await fixture();await fs.writeFile(path.join(f.source,"bridge.mjs"),"private-token");await expect(stageManagedCommand(f.config)).rejects.toThrow("Managed command");});
it("rejects traversal duplicate absent entrypoint and symlink",async()=>{
 const f=await fixture();
 for(const c of [{...f.config,entrypoint:"../wrapper.mjs"},{...f.config,files:[...f.config.files,f.config.files[0]]},{...f.config,files:f.config.files.slice(1)},{...f.config,files:[{path:"/etc/passwd",sha256:"a".repeat(64)}]}])await expect(stageManagedCommand(c)).rejects.toThrow();
 await fs.rename(path.join(f.source,"bridge.mjs"),path.join(f.source,"real.mjs"));await fs.symlink("real.mjs",path.join(f.source,"bridge.mjs"));await expect(stageManagedCommand(f.config)).rejects.toThrow();
});
it("rejects symlinked source directory",async()=>{const f=await fixture();const link=path.join(f.root,"link");await fs.symlink(f.source,link);await expect(stageManagedCommand({...f.config,sourceDir:link})).rejects.toThrow();});


it("rejects nonregular FIFO without blocking",async()=>{
 const f=await fixture();await fs.unlink(path.join(f.source,"bridge.mjs"));execFileSync("mkfifo",[path.join(f.source,"bridge.mjs")]);
 await expect(stageManagedCommand(f.config)).rejects.toThrow("Managed command");
},2000);
it("rejects parent-directory symlinks and excessive manifest count",async()=>{
 const f=await fixture();await fs.mkdir(path.join(f.source,"sub"));await fs.symlink(f.source,path.join(f.source,"alias"));
 await expect(stageManagedCommand({...f.config,files:[{path:"alias/bridge.mjs",sha256:f.config.files[1].sha256}]})).rejects.toThrow();
 await expect(stageManagedCommand({...f.config,files:Array(17).fill(f.config.files[0])})).rejects.toThrow();
});
it("bounds reads if the source grows after stat",async()=>{
 const f=await fixture();const original=fs.open.bind(fs);
 vi.spyOn(fs,"open").mockImplementation(async(...args)=>{
   const h=await original(...args);
   if(String(args[0]).endsWith("bridge.mjs")){
     const stat=h.stat.bind(h);
     h.stat=(async(...statArgs: Parameters<typeof h.stat>)=>{const result=await stat(...statArgs);await fs.appendFile(String(args[0]),Buffer.alloc(1024*1024+1));return result;}) as typeof h.stat;
   }return h;
 });
 await expect(stageManagedCommand(f.config)).rejects.toThrow("Managed command");
});
it("cleans partial snapshot on write failure",async()=>{
 const f=await fixture();const original=fs.writeFile.bind(fs);let snapshot="";
 vi.spyOn(fs,"writeFile").mockImplementation(async(...args)=>{
   if(String(args[0]).includes("paperclip-managed-command-")){
     snapshot=path.dirname(String(args[0]));throw new Error("fixture failure");
   }return original(...args);
 });
 await expect(stageManagedCommand(f.config)).rejects.toThrow("fixture failure");
 expect(snapshot).not.toBe("");await expect(fs.access(snapshot)).rejects.toThrow();
});
it("rejects oversized single and aggregate packages",async()=>{
 const f=await fixture();const big=Buffer.alloc(1024*1024+1);await fs.writeFile(path.join(f.source,"bridge.mjs"),big);
 await expect(stageManagedCommand(f.config)).rejects.toThrow();
 const files=[];for(let i=0;i<3;i++){const name="p"+i+".mjs";const bytes=Buffer.alloc(800000);await fs.writeFile(path.join(f.source,name),bytes);files.push({path:name,sha256:createHash("sha256").update(bytes).digest("hex")});}
 await expect(stageManagedCommand({sourceDir:f.source,entrypoint:"p0.mjs",files})).rejects.toThrow();
});
