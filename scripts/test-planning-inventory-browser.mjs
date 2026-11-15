
import { build } from 'esbuild';
import { mkdtemp,readFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';import { join,resolve } from 'node:path';
import { createServer } from 'node:http';import assert from 'node:assert/strict';
const {chromium}=await import(process.env.PORTAL_PLAYWRIGHT_MODULE);
const temp=await mkdtemp(join(tmpdir(),'planning-browser-'));let server,browser;
try{
 await build({entryPoints:['scripts/fixtures/planning-inventory/entry.tsx'],outfile:join(temp,'app.js'),bundle:true,format:'esm',platform:'browser',jsx:'automatic',
 alias:{react:resolve('ui/node_modules/react'),'react-dom':resolve('ui/node_modules/react-dom'),'@tanstack/react-query':resolve('ui/node_modules/@tanstack/react-query')},
 plugins:[{name:'fixture-boundaries',setup(b){b.onResolve({filter:/^\.\.\/(context\/CompanyContext|api\/(companies-query|client))$/},()=>({path:resolve('scripts/fixtures/planning-inventory/boundaries.js')}));}}]});
 const js=await readFile(join(temp,'app.js'));server=createServer((req,res)=>{res.setHeader('content-type',req.url==='/app.js'?'text/javascript':'text/html; charset=utf-8');res.end(req.url==='/app.js'?js:'<div id="root"></div><script type="module" src="/app.js"></script>');});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 browser=await chromium.launch({headless:true});const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:'+server.address().port);
 await page.getByRole('heading',{name:'Task one',exact:true}).waitFor();
 assert.match(await page.textContent('body'),/not the full backlog/);
 await page.evaluate(()=>window.change({loading:true}));assert.equal(await page.locator('article').count(),0);
 await page.evaluate(()=>window.change({loading:false}));await page.getByRole('heading',{name:'Task one',exact:true}).waitFor();
 await page.evaluate(()=>{window.slow=true;});await page.getByRole('button',{name:'Refresh inventory'}).click();
 await page.evaluate(()=>window.change({userId:'two'}));assert.equal(await page.locator('article').count(),0);
 await page.evaluate(()=>{window.slow=false;window.pending.splice(0).forEach(resolve=>resolve());});
 await page.getByRole('heading',{name:'Task two',exact:true}).waitFor();
 assert.equal(await page.getByRole('heading',{name:'Task one',exact:true}).count(),0);
 await page.evaluate(()=>window.change({userId:null}));assert.equal(await page.locator('article').count(),0);
 await page.evaluate(()=>window.change({userId:'two',companyId:'c2'}));await page.getByRole('heading',{name:'Task two',exact:true}).waitFor();
 assert.ok(await page.evaluate(()=>window.calls.some(c=>c.company==='c2')));
 await page.evaluate(()=>{window.fail=true;});await page.getByRole('button',{name:'Refresh inventory'}).click();await page.getByRole('alert').waitFor();assert.equal(await page.locator('article').count(),0);
 assert.deepEqual(errors,[]);console.log(JSON.stringify({checks:8,pageErrors:errors,scope:'real Chromium and React Query; synthetic identity/API; no live auth'}));
}finally{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));await rm(temp,{recursive:true,force:true});}
