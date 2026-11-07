import re, sys, time, pyotp, asyncio
from playwright.async_api import async_playwright
log = open('/tmp/srv.log').read()
creds = dict((u, (p, k)) for u, p, k in re.findall(r"enrollment: (\S+) .*?\n\s+temporary password : (\S+)\n\s+authenticator key  : (\S+)", log))
URL = "https://127.0.0.1:8443/"
NEWPW = "a much longer passphrase 2026"
used = {}
async def code(user):
    k = creds[user][1]
    # wait for a fresh 30s step (replay protection)
    while used.get(user) == int(time.time()//30): await asyncio.sleep(1)
    used[user] = int(time.time()//30)
    return pyotp.TOTP(k).now()
async def login(page, user):
    await page.goto(URL); await page.fill('#u', user); await page.fill('#p', creds[user][0]); await page.fill('#c', await code(user))
    await page.click('button[type=submit]')
    await page.wait_for_selector('text=Temporary password', timeout=5000)
    pw = page.locator('input[type=password]')
    await pw.nth(0).fill(creds[user][0]); await pw.nth(1).fill(NEWPW); await pw.nth(2).fill(NEWPW)
    await page.click('text=Save new password')
    await page.wait_for_selector('#comms', timeout=8000)
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch()
        errs = []
        ctxA = await b.new_context(ignore_https_errors=True, viewport={'width':1500,'height':950})
        ctxB = await b.new_context(ignore_https_errors=True, viewport={'width':1500,'height':950})
        A = await ctxA.new_page(); B = await ctxB.new_page()
        for pg in (A,B): pg.on('console', lambda m: errs.append(m.text) if m.type=='error' else None); pg.on('pageerror', lambda e: errs.append(str(e)))
        await A.goto(URL); await A.screenshot(path='/home/claude/shots/01-login.png')
        await login(A, 'ic.rivera')
        await A.wait_for_selector('text=Do this next'); await asyncio.sleep(1)
        await A.screenshot(path='/home/claude/shots/02-incident.png')
        await login(B, 'ceo.patel')
        await B.wait_for_selector('text=Do this next')
        # privileged entry hidden from viewer
        await B.click('button.tab:has-text("Timeline")'); await asyncio.sleep(.5)
        txtB = await B.inner_text('#tl-list'); print('viewer sees privileged?', 'Counsel engaged; forensics' in txtB)
        await A.click('button.tab:has-text("Timeline")'); await asyncio.sleep(.5)
        print('commander sees privileged?', 'Counsel engaged; forensics' in await A.inner_text('#tl-list'))
        await A.screenshot(path='/home/claude/shots/04-timeline.png')
        # realtime urgent chat A -> B
        await A.fill('#composer', 'Everyone: assume VPN is compromised. Use hotspot only.')
        await A.check('.composer input[type=checkbox] >> nth=0'); await A.click('.composer button:has-text("Send")')
        await B.wait_for_selector('.banner-urgent', timeout=5000); print('urgent banner reached viewer: yes')
        await B.screenshot(path='/home/claude/shots/05-urgent-viewer.png')
        # realtime scope status change visible on B
        await A.click('button.tab:has-text("Affected data")'); await B.click('button.tab:has-text("Affected data")'); await asyncio.sleep(.5)
        await A.locator('#scope-body tbody tr').nth(3).locator('select').first.select_option('Contained')
        await asyncio.sleep(1.2)
        print('viewer sees Contained live:', 'Contained' in await B.inner_text('#scope-body tbody'))
        await A.screenshot(path='/home/claude/shots/03-scope.png')
        await A.click('text=＋ Add affected data'); await asyncio.sleep(.4); await A.screenshot(path='/home/claude/shots/06-scope-form.png')
        await A.keyboard.press('Escape')
        await A.click('button.tab:has-text("Overview")'); await asyncio.sleep(.4); await A.screenshot(path='/home/claude/shots/07-overview.png', full_page=True)
        await A.click('button.tab:has-text("Report")'); await asyncio.sleep(.4); await A.screenshot(path='/home/claude/shots/08-report.png')
        # viewer cannot edit
        dis = await B.locator('#scope-body select').count(); print('viewer has edit controls:', dis)
        # admin flow
        C = await (await b.new_context(ignore_https_errors=True, viewport={'width':1500,'height':950})).new_page()
        C.on('pageerror', lambda e: errs.append(str(e)))
        await login(C, 'admin')
        await C.click('text=Team & Access'); await asyncio.sleep(.5)
        await C.fill('input[placeholder^="Full name"]', 'Alex Kim'); await C.click('text=Add person & create sign-in card')
        await C.wait_for_selector('text=Sign-in card for Alex Kim'); await C.screenshot(path='/home/claude/shots/09-enroll.png')
        await C.keyboard.press('Escape'); await C.click('text=Audit log'); await C.click('text=Verify audit log integrity')
        await C.wait_for_selector('.okbox'); print('audit:', (await C.inner_text('.okbox'))[:60])
        await C.screenshot(path='/home/claude/shots/10-audit.png')
        await C.keyboard.press('Escape')
        # declare incident as IC
        await A.click('text=＋ Declare new incident'); await A.fill('input[placeholder^="e.g. Files"]', 'CFO mailbox forwarding rule found')
        await A.click('.seg button:has-text("Business Email Compromise")'); await A.screenshot(path='/home/claude/shots/11-declare.png')
        await A.click('text=🚨 Declare incident'); await A.wait_for_selector('h2:has-text("CFO mailbox")'); await asyncio.sleep(1.5)
        print('B sidebar updated live:', 'CFO mailbox' in await B.inner_text('#side'))
        # lockdown
        await C.click('text=Lockdown'); await C.fill('input[placeholder="Type LOCKDOWN"]', 'LOCKDOWN'); await C.click('text=Sign everyone out now')
        await B.wait_for_selector('#u', timeout=5000); print('lockdown kicked viewer: yes')
        await B.screenshot(path='/home/claude/shots/12-after-lockdown.png')
        print('JS errors:', errs)
        await b.close()
asyncio.run(main())
