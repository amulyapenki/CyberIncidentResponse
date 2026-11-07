import re, time, pyotp, asyncio, hashlib
from playwright.async_api import async_playwright
log=open('/tmp/srv.log').read()
creds=dict((u,(p,k)) for u,p,k in re.findall(r"enrollment: (\S+) .*?\n\s+temporary password : (\S+)\n\s+authenticator key  : (\S+)", log))
URL="https://127.0.0.1:8443/"; NEWPW="a much longer passphrase 2026"; used={}
async def code(u):
    while used.get(u)==int(time.time()//30): await asyncio.sleep(1)
    used[u]=int(time.time()//30); return pyotp.TOTP(creds[u][1]).now()
async def login(pg,u):
    await pg.goto(URL); await pg.fill('#u',u); await pg.fill('#p',creds[u][0]); await pg.fill('#c',await code(u)); await pg.click('button[type=submit]')
    await pg.wait_for_selector('text=Temporary password'); pw=pg.locator('input[type=password]')
    await pw.nth(0).fill(creds[u][0]); await pw.nth(1).fill(NEWPW); await pw.nth(2).fill(NEWPW); await pg.click('text=Save new password'); await pg.wait_for_selector('#comms')
async def main():
    async with async_playwright() as p:
        b=await p.chromium.launch(); errs=[]
        mk=lambda: b.new_context(ignore_https_errors=True, viewport={'width':1500,'height':950}, timezone_id='America/Chicago', accept_downloads=True)
        A=await (await mk()).new_page(); B=await (await mk()).new_page()
        for pg in (A,B): pg.on('pageerror', lambda e: errs.append(str(e)))
        await login(A,'ic.rivera'); await A.wait_for_selector('.iclock'); await asyncio.sleep(1.2)
        print('header clock:', (await A.inner_text('.iclock')).replace('\n',' | '))
        print('topbar clock:', await A.inner_text('#clock'))
        print('phase times:', [t for t in await A.locator('.phase .pt').all_inner_texts()])
        await A.screenshot(path='/home/claude/shots/v2-01-incident.png')
        await A.click('text=🕘 Change history'); await asyncio.sleep(.3); await A.screenshot(path='/home/claude/shots/v2-02-history.png'); await A.keyboard.press('Escape')
        await A.click('button.tab:has-text("Timeline")'); await asyncio.sleep(.4); await A.locator('#tl-list').scroll_into_view_if_needed(); await A.screenshot(path='/home/claude/shots/v2-03-timeline.png')
        await A.fill('input[placeholder^="🔎"]','VPN'); await asyncio.sleep(.3); print('filter:', await A.inner_text('#tl-list >> .small.muted'))
        await A.fill('input[placeholder^="🔎"]','')
        # evidence upload + download with hash check
        await A.click('button.tab:has-text("Evidence")'); await asyncio.sleep(.3)
        data=b'Received: from evil.example\nSubject: Urgent wire\n'*50; open('/tmp/phish.eml','wb').write(data)
        await A.set_input_files('input.filein','/tmp/phish.eml'); await A.fill('input[placeholder^="What is it"]','Phishing email sent to CFO')
        await A.click('text=🔒 Seal & upload'); await A.wait_for_selector('text=Sealed. SHA-256')
        print('upload hash ok:', hashlib.sha256(data).hexdigest()[:16] in await A.inner_text('#ev-list'))
        async with A.expect_download() as dl: await A.locator('#ev-list a:has-text("Download")').first.click()
        d=await dl.value; got=open(await d.path(),'rb').read(); print('download byte-identical:', got==data, 'name:', d.suggested_filename)
        await asyncio.sleep(1); await A.locator('#ev-list details').first.click(); await asyncio.sleep(.3)
        print('custody:', (await A.locator('#ev-list details').first.inner_text()).replace('\n',' | ')[:220])
        await A.locator('#ev-list').scroll_into_view_if_needed(); await A.screenshot(path='/home/claude/shots/v2-04-evidence.png')
        # scope history + overview metrics
        await A.click('button.tab:has-text("Affected data")'); await asyncio.sleep(.3)
        await A.locator('#scope-body tbody tr').nth(3).locator('select').first.select_option('Contained'); await asyncio.sleep(.8)
        await A.locator('.linkbtn:has-text("history")').nth(3).click(); await asyncio.sleep(.3); await A.screenshot(path='/home/claude/shots/v2-05-scope-history.png'); await A.keyboard.press('Escape')
        await A.click('button.tab:has-text("Overview")'); await asyncio.sleep(.3)
        print('metrics:', (await A.inner_text('.metrics')).replace('\n',' | '))
        await A.locator('.metrics').scroll_into_view_if_needed(); await A.screenshot(path='/home/claude/shots/v2-06-metrics.png')
        # unread badge on viewer
        await login(B,'ceo.patel'); await B.click('#chan button:has-text("Whole team")'); await asyncio.sleep(.3)
        await A.fill('#composer','Containment update at the top of the hour.'); await A.press('#composer','Enter'); await asyncio.sleep(1)
        print('viewer unread badge:', await B.locator('#chan .badge').all_inner_texts())
        print('viewer evidence download link present:', await B.locator('#ev-list a').count() if await B.locator('#ev-list').count() else 'n/a')
        # UTC toggle
        await A.click('#tzbtn'); await asyncio.sleep(.5); print('after UTC toggle header:', (await A.inner_text('.ref'))[-40:])
        await A.click('button.tab:has-text("Report")'); await asyncio.sleep(.4); await A.screenshot(path='/home/claude/shots/v2-07-report-utc.png', full_page=True)
        print('JS errors:', errs); await b.close()
asyncio.run(main())
