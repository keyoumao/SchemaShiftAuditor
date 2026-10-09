// Optional developer check. npm install playwright; npx playwright install chromium
const fs=require('fs');const path=require('path');const {pathToFileURL}=require('url');
const {chromium}=require(process.env.SCHEMASHIFT_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const root=path.resolve(__dirname,'..');
 const launch={headless:true,args:['--no-sandbox']};
 if(process.env.SCHEMASHIFT_CHROMIUM_MODULE){const module=await import(process.env.SCHEMASHIFT_CHROMIUM_MODULE);const binary=module.default||module;launch.executablePath=await binary.executablePath();launch.args=binary.args;}
 const browser=await chromium.launch(launch);
 const context=await browser.newContext({viewport:{width:1440,height:1080},offline:true,recordVideo:{dir:path.join(__dirname,'browser-capture'),size:{width:1440,height:1080}}});
 const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(pathToFileURL(path.join(root,'demo/index.html')).href);
 await page.locator('#scores tr').first().waitFor();
 if(await page.locator('#scores tr').count()!==3)throw Error('Expected three initial variant rows');
 if(!(await page.locator('#banner').textContent()).includes('ILLUSTRATIVE FIXTURES'))throw Error('Fixture banner missing');
 if(!(await page.locator('#scores tr').first().textContent()).includes('2/5 · 40%'))throw Error('Raw counts incorrect');
 if(!(await page.locator('#sponsorStatus').textContent()).includes('2/3'))throw Error('Sponsor usage overstated');
 if(!(await page.locator('#clickhouseEvidence').textContent()).includes('20 fixture traces'))throw Error('ClickHouse provenance missing');
 if(!(await page.locator('#semgrepEvidence').textContent()).includes('1 confirmed replay path traversal'))throw Error('Semgrep finding missing');
 await page.evaluate(()=>window.scrollTo(0,0));
 await page.screenshot({path:path.join(root,'demo/dashboard.png'),fullPage:false});
 await page.waitForTimeout(4000);
 await page.locator('#normalize').click();
 if(await page.locator('#scores tr').count()!==4)throw Error('Normalization did not reveal cached row');
 if(!(await page.locator('#beforeafter').textContent()).includes('2/5 · 40%'))throw Error('Before/after incorrect');
 await page.locator('#hardening').scrollIntoViewIfNeeded();await page.waitForTimeout(4000);
 await page.locator('#mode').click();
 await page.locator('#traces details').first().locator('summary').click();
 await page.locator('#traces details').first().scrollIntoViewIfNeeded();
 if(!(await page.locator('.stage').first().textContent()).includes('Simulated commit'))throw Error('Stage labeling missing');
 await page.waitForTimeout(4000);
 if(errors.length)throw Error(errors.join('\n'));
 const video=page.video();await context.close();
 fs.copyFileSync(await video.path(),path.join(root,'demo/backup-walkthrough.webm'));
 await browser.close();console.log('PASS: file:// offline counts, normalization, trace expansion, stage view; backup recorded.');
})().catch(e=>{console.error(e);process.exit(1)});
