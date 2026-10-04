import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright-core';
import AxeBuilder from '@axe-core/playwright';
const server=createServer(async(req,res)=> {
  const name = new Map([['/','index.html'],['/app.js','app.js'],['/pools.js','pools.js'],['/style.css','style.css']]).get(req.url);
  if (!name) { res.writeHead(404).end(); return; }
  res.setHeader('Content-Type',name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':'text/html');
  res.end(await readFile(new URL(`../ui/${name}`,import.meta.url)));
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const browser=await chromium.launch(process.env.WILDBLOOM_BROWSER_EXECUTABLE ? {executablePath:process.env.WILDBLOOM_BROWSER_EXECUTABLE} : process.platform==='darwin' ? {executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'} : {});
try {
  const context=await browser.newContext();
  const page=await context.newPage(); const errors=[]; const unexpected=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('request',r=> { if(new URL(r.url()).hostname!=='127.0.0.1') unexpected.push(r.url()); });
  await page.addInitScript(()=> {
    window.calls=[];
    window.poolFixture={ inspection:{ receipt_id:'a'.repeat(64),owner:'b'.repeat(64),storage_verified:false,manifest:{mode:'erasure',profile:'direct',required:2,total:4,copies:1,payload:{size:4096,sha256:'c'.repeat(64)},parts:Array.from({length:4},(_,i)=>({index:i,size:2048,targets:[{id:`node-${i}`,origin:`https://node-${i}.example/`,failure_group:`site-${i}`}]}))}},phase:'stopped',detail:'Receipt verified locally.',expires_at:null,started_at:null,report:null,work_dir:'/private/owner-pools/example/work'};
    let imported=false;
    window.__TAURI__={core:{invoke:async(command,args)=> {
      window.calls.push({command,args});
      if(command==='node_status')return {phase:'setup',phaseLabel:'Setup required',detail:'Choose transport.',settings:{friendGrants:[],quotaGib:10,transport:'tor',directPort:3742}};
      if(command==='pool_status')return {pools:imported?[structuredClone(window.poolFixture)]:[],error:null};
      if(command==='import_pool') { if(args.owner!=='b'.repeat(64))throw 'Wrong owner'; imported=true; return window.poolFixture.inspection; }
      if(command==='start_pool') { window.poolFixture.phase=args.settings.checkOnly?'checking':'repairing'; return; }
      if(command==='stop_pool') { window.poolFixture.phase='stopped'; return; }
      if(command==='remove_pool') { imported=false; return; }
      if(command==='open_pool_client')return;
      throw `Unexpected command ${command}`;
    }}};
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.waitForFunction(()=>window.calls.some(c=>c.command==='pool_status'));
  assert.deepEqual(await page.evaluate(()=>[...new Set(window.calls.map(c=>c.command))].sort()),['node_status','pool_status']);
  await page.locator('#pool-receipt').setInputFiles({name:'receipt.json',mimeType:'application/json',buffer:Buffer.from('{}')});
  await page.locator('#pool-owner').fill('b'.repeat(64));
  await page.locator('#pool-import').click();
  await page.locator('#pool-details').waitFor({state:'visible'});
  assert.match(await page.locator('#pool-health').textContent(),/not yet verified/);
  assert.equal(await page.locator('#pool-start').isDisabled(),true);
  await page.locator('#pool-consent').check();
  assert.equal(await page.locator('#pool-start').isEnabled(),true);
  await page.locator('#pool-transfer').fill('9');
  assert.equal(await page.locator('#pool-consent').isChecked(),false);
  await page.locator('#pool-check').click();
  const check=await page.evaluate(()=>window.calls.find(c=>c.command==='start_pool').args.settings);
  assert.equal(check.checkOnly,true); assert.equal(check.allowReconstruction,false);assert.equal(check.signer,'');assert.deepEqual(check.signerArguments,[]);
  await page.locator('#pool-stop').click();
  await page.locator('#pool-signer').fill('/owner/signer');
  await page.locator('#pool-signer-arguments').fill('--account\nowner');
  await page.locator('#pool-consent').check();await page.locator('#pool-start').click();
  const repair=await page.evaluate(()=>window.calls.filter(c=>c.command==='start_pool').at(-1).args.settings);
  assert.equal(repair.allowReconstruction,true);assert.equal(repair.checkOnly,false);assert.equal(repair.signer,'/owner/signer');assert.deepEqual(repair.signerArguments,['--account','owner']);
  assert.equal(await page.locator('#pool-remove').isDisabled(),true);
  await page.locator('#pool-stop').click();
  await page.evaluate(()=> {
    window.poolFixture.report={observed_at:Math.floor(Date.now()/1000),protected:false,recoverable:true,reconstructed:false,uploads_attempted:0,verified_groups:[1,1,0,0],nodes:[{id:'node-0',part_index:0,state:'verified'}]};
    window.poolFixture.inspection.manifest.parts[0].targets[0].failure_group='<img src=x onerror=alert(1)>';
  });
  await page.waitForFunction(()=>document.querySelector('#pool-health').textContent.includes('Needs repair'));
  assert.equal(await page.locator('#pool-parts img').count(),0);
  assert.match(await page.locator('#pool-parts').textContent(),/<img src=x/);
  for(const width of [820,420,320]) {
    await page.setViewportSize({width,height:900});
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth ? [...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > innerWidth).map(e => ({ tag: e.tagName, id: e.id, right: e.getBoundingClientRect().right })) : []);
    assert.deepEqual(overflow, [], `overflow at ${width}: ${JSON.stringify(overflow)}`);
    const axe=await new AxeBuilder({page}).include('#owner-pools').withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();
    assert.deepEqual(axe.violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[]);
    if(process.env.WILDBLOOM_SCREENSHOT_DIR)await page.locator('#owner-pools').screenshot({path:`${process.env.WILDBLOOM_SCREENSHOT_DIR}/pools-${width}.png`});
  }
  await page.locator('#owner-pools summary').click();
  await page.locator('#pool-remove-consent').check();await page.locator('#pool-remove').click();
  await page.locator('#pool-details').waitFor({state:'hidden'});
  assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[]);
  console.log('Desktop pool UI passed: explicit actions, read-only authority, consent reset, signer arguments, stop/remove, hostile text, responsive layouts and accessibility. IPC is mocked; native daemon contracts are tested separately.');
} finally {await browser.close();await new Promise(r=>server.close(r));}
