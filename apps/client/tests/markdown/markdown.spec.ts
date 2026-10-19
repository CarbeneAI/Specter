import { expect, test, type Page } from '@playwright/test';

const networkAttempts: string[] = [];

test.beforeEach(async ({ page, baseURL }) => {
  networkAttempts.length = 0;
  let fixtureLoaded = false;
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (!fixtureLoaded && url.origin === baseURL) return route.continue();
    networkAttempts.push(url.href);
    return route.abort();
  });
  await page.goto('/tests/markdown/fixture.html');
  await page.waitForFunction(() => typeof (window as any).setMarkdown === 'function');
  fixtureLoaded = true;
});

async function render(page: Page, content: string) {
  await page.evaluate(async value => (window as any).setMarkdown(value), content);
  return page.locator('#app .prose');
}

test('preserves headings, tables, lists, emphasis, and fenced code', async ({ page }) => {
  const body = await render(page, '# Findings\n\n**Bold** and *emphasis*\n\n- One\n- Two\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n```html\n<img src=x onerror=alert(1)>\n```');
  await expect(body.locator('h1')).toHaveText('Findings');
  await expect(body.locator('strong')).toHaveText('Bold');
  await expect(body.locator('em')).toHaveText('emphasis');
  await expect(body.locator('li')).toHaveCount(2);
  await expect(body.locator('table tbody td')).toHaveCount(2);
  await expect(body.locator('pre code')).toHaveText('<img src=x onerror=alert(1)>\n');
  await expect(body.locator('img')).toHaveCount(0);
});

test('removes active HTML, event handlers, namespaces, styles, and clobbering names', async ({ page }) => {
  const body = await render(page, '<script>window.fixtureXss = true</script><p onclick="window.fixtureXss=true" style="position:fixed" id="location" name="document">Evidence</p><svg onload="window.fixtureXss=true"><a xlink:href="javascript:alert(1)">svg</a></svg><math><mi>math</mi></math><form><input name="location"></form><iframe srcdoc="<script>alert(1)</script>"></iframe>');
  await expect(body.locator('script, svg, math, form, input, iframe, style')).toHaveCount(0);
  await expect(body.locator('[onclick], [onload], [style], [id], [name]')).toHaveCount(0);
  await expect(body).toContainText('Evidence');
  expect(await page.evaluate(() => (window as any).fixtureXss)).toBeUndefined();
});

test('permits only absolute HTTP(S) hrefs after entity decoding', async ({ page }) => {
  const unsafe = ['javascript:alert(1)', 'java&#x73;cript:alert(1)', 'java&#x09;script:alert(1)', 'java&#10;script:alert(1)', '&#106;avascript:alert(1)', '%6aavascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'vbscript:msgbox(1)', 'file:///etc/passwd', '//example.invalid/path', '/settings', '#fragment', 'mailto:someone@example.invalid', 'ftp://example.invalid', 'blob:https://example.invalid/fixture', 'javascript:https://example.invalid', '  javascript:alert(1)'];
  const content = unsafe.map((url, i) => `<a href="${url}">unsafe${i}</a>`).join('\n') + '\n\n[markdown unsafe](javascript:alert%281%29)\n\n[Secure](https://example.com/path?q=1&x=2) [Plain](http://example.com/)';
  const body = await render(page, content);
  await expect(body.locator('a[href]')).toHaveCount(2);
  await expect(body.getByRole('link', { name: 'Secure', exact: true })).toHaveAttribute('href', 'https://example.com/path?q=1&x=2');
  await expect(body.getByRole('link', { name: 'Plain', exact: true })).toHaveAttribute('href', 'http://example.com/');
  await expect(body.locator('[target], [ping], [download]')).toHaveCount(0);
});

test('does not embed or fetch model supplied resources', async ({ page }) => {
  const body = await render(page, '![tracking](https://example.invalid/tracker.png)\n\n<img srcset="https://example.invalid/tracker2.png 2x" style="background:url(https://example.invalid/style-image)" src="/settings" onerror="window.fixtureXss=true"><video poster="https://example.invalid/poster"><source src="https://example.invalid/media"></video><audio src="https://example.invalid/sound"></audio><object data="https://example.invalid/payload"></object><link rel="stylesheet" href="https://example.invalid/style"><style>@import "https://example.invalid/css";</style>');
  await expect(body.locator('img, video, audio, source, object, link, style')).toHaveCount(0);
  await page.waitForTimeout(100);
  expect(networkAttempts).toEqual([]);
  expect(await page.evaluate(() => (window as any).fixtureXss)).toBeUndefined();
});

test('sanitizes malformed namespace and mutation payloads', async ({ page }) => {
  const body = await render(page, '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror="window.fixtureXss=true">"></math><svg><g/onload=window.fixtureXss=true//<p>Visible');
  await expect(body.locator('math, svg, style, img, [onload], [onerror]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).fixtureXss)).toBeUndefined();
});

test('reapplies safety when a message changes', async ({ page }) => {
  await render(page, '**Initial**');
  const body = await render(page, '**Updated** <img src=x onerror="window.fixtureXss=true"> <a href="javascript:alert(1)">unsafe</a>');
  await expect(body.locator('strong')).toHaveText('Updated');
  await expect(body.locator('img, [onerror], a[href]')).toHaveCount(0);
});

test('fails closed when the sanitizer is unsupported', async ({ page }) => {
  await page.evaluate(() => (window as any).disableSanitizer());
  const body = await render(page, '**Untrusted** <img src=x onerror="window.fixtureXss=true">');
  await expect(body).toBeEmpty();
  expect(networkAttempts).toEqual([]);
});
