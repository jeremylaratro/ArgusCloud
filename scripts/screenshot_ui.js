const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
  await page.goto('http://127.0.0.1:8001', { waitUntil: 'networkidle' });

  // Settings: set API base and theme
  await page.click('text=Settings');
  await page.fill('#apiBase', 'http://127.0.0.1:5000');
  await page.selectOption('#theme', 'dark');

  // Data Management: fetch from API
  await page.click('text=Data Management');
  await page.click('#fetchApiBtn');
  await page.waitForTimeout(1500);

  // Graph tab screenshot
  await page.click('text=Graph');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: 'screenshot-graph.png', fullPage: true });

  // Environment tab screenshot
  await page.click('text=Environment');
  await page.waitForTimeout(500);
  await page.screenshot({ path: 'screenshot-environment.png', fullPage: true });

  // Data Management tab screenshot
  await page.click('text=Data Management');
  await page.waitForTimeout(500);
  await page.screenshot({ path: 'screenshot-data.png', fullPage: true });

  await browser.close();
})();
