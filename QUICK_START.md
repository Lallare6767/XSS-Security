# 🚀 XSS Guardian - Quick Start Guide

Get started with XSS Guardian in under 2 minutes!

## Method 1: Bookmarklet (Easiest - No Installation)

### Step 1: Install the Bookmarklet

1. Open `bookmarklet.html` in your browser
2. Drag the **🛡️ XSS Guardian** button to your bookmarks bar

### Step 2: Use It

1. Navigate to any website you want to scan
2. Click the XSS Guardian bookmarklet in your bookmarks
3. Open the browser console (Press F12)
4. View the security report!

**That's it!** 🎉

---

## Method 2: Browser Console (Quick Testing)

### Copy & Paste This Code

Open your browser console (F12) on any page and paste:

```javascript
(function() {
  var script = document.createElement('script');
  script.src = 'https://cdn.jsdelivr.net/gh/yourusername/xss-guardian@main/dist/xss-guardian.js';
  script.onload = function() {
    console.log('🛡️ XSS Guardian loaded!');
    XSSGuardian.quickScan();
  };
  document.head.appendChild(script);
})();
```

Wait a few seconds and see the results!

---

## Method 3: Local Testing (For Developers)

### Install and Build

```bash
# Clone the repository
git clone https://github.com/yourusername/xss-guardian.git
cd xss-guardian

# Install dependencies
npm install

# Build the project
npm run build

# Open the example page
open examples/basic-usage.html
```

Click any button in the example page and check the console!

---

## Method 4: NPM Package (For Projects)

### Install

```bash
npm install xss-guardian
```

### Use in Your Code

```javascript
import XSSGuardian from 'xss-guardian';

// Run a quick scan
const guardian = XSSGuardian.create();
const result = await guardian.quickScan();

console.log(`Found ${result.summary.total} vulnerabilities!`);
```

---

## Understanding the Results

### Severity Levels

- 🔴 **CRITICAL**: Confirmed exploitable (payload executed!)
- 🟠 **HIGH**: Likely exploitable with right payload
- 🟡 **MEDIUM**: Potentially exploitable in certain conditions
- 🟢 **LOW**: Suspicious but low risk
- 🔵 **INFO**: Informational finding

### What to Do With Findings

1. **Review Each Vulnerability**: Click on elements in console to see location
2. **Read Remediation Advice**: Each finding has specific fix suggestions
3. **Export Report**: `XSSGuardian.exportReport(result, 'html')`
4. **Fix Issues**: Implement the recommended fixes
5. **Re-scan**: Run another scan to verify fixes

---

## Common Commands

```javascript
// Quick scan (fast, recommended for first scan)
await XSSGuardian.quickScan();

// Deep scan (comprehensive, includes mutation testing)
await XSSGuardian.deepScan();

// Custom scan with options
await XSSGuardian.scan({
  depth: 20,
  includeShadowDOM: true,
  mutationTest: false,
  payloadComplexity: 'advanced'
});

// Framework-specific scan
await XSSGuardian.frameworkScan(['react', 'vue']);

// Export report
XSSGuardian.exportReport(lastResult, 'html'); // or 'json'
```

---

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║           🛡️  XSS GUARDIAN SECURITY SCANNER 🛡️             ║
╚══════════════════════════════════════════════════════════════╝

🛡️ SCAN SUMMARY
────────────────────────────────────────────────────────────
Total Vulnerabilities Found: 3

Breakdown by Severity:
  🔴 CRITICAL: 1
  🟠 HIGH: 1
  🟡 MEDIUM: 1

Scan Duration: 127.45ms
Timestamp: 11/17/2024, 10:30:15 AM

🔵 DETECTED FRAMEWORKS
────────────────────────────────────────────────────────────
  ✓ React
  ✓ Tailwind

🐛 VULNERABILITY DETAILS
════════════════════════════════════════════════════════════

🔴 CRITICAL SEVERITY (1)

[1] DOM_XSS
    Description: React dangerouslySetInnerHTML usage detected
    Sink: dangerouslySetInnerHTML
    Source: react-prop
    Context: html
    Framework: React
    Remediation: Sanitize HTML with DOMPurify before using...
```

---

## Tips for Best Results

### ✅ Do's

- **Start with Quick Scan**: Fast and safe
- **Run on Development/Test Sites**: Not production!
- **Get Permission**: Always have authorization
- **Export Reports**: Save findings for documentation
- **Fix and Re-scan**: Verify your fixes work

### ❌ Don'ts

- **Don't run on production** without permission
- **Don't run Deep Scan** on live sites (it modifies the page)
- **Don't test sites you don't own** without written authorization
- **Don't ignore findings**: Even "Low" severity issues matter
- **Don't share exploits publicly** before responsible disclosure

---

## Need Help?

### Documentation
- Full README: [README.md](README.md)
- API Docs: Check TypeScript definitions
- Examples: See `examples/` folder

### Common Issues

**Q: Bookmarklet doesn't work?**
- Make sure your bookmarks bar is visible
- Try the console method instead
- Check browser console for errors

**Q: No vulnerabilities found?**
- Great! Your site might be secure
- Try Deep Scan for more thorough testing
- Check if frameworks were detected

**Q: Too many false positives?**
- Review the severity levels
- Focus on CRITICAL and HIGH first
- Check the context of each finding

**Q: Can I use this in CI/CD?**
- Yes! Install via NPM and integrate into your pipeline
- Export results as JSON for automation

### Get Support

- GitHub Issues: [Report bugs/questions](https://github.com/yourusername/xss-guardian/issues)
- Security: security@example.com
- Twitter: @xssguardian

---

## What's Next?

1. ✅ **Run your first scan** (you just did!)
2. 📊 **Review the findings** in detail
3. 🔧 **Fix the vulnerabilities** using remediation advice
4. 🧪 **Re-scan** to verify fixes
5. 📄 **Export report** for documentation
6. 🔄 **Make it part of your workflow** (weekly/monthly scans)

---

## Stay Safe! 🛡️

Remember:
- 🔒 **Security is a process**, not a one-time thing
- 📚 **Keep learning** about XSS and web security
- 🤝 **Share knowledge** with your team
- ⚖️ **Test ethically** and responsibly

**Happy Scanning!** 🎉

---

[Back to Full Documentation](README.md) | [View Examples](examples/) | [Report Issues](https://github.com/yourusername/xss-guardian/issues)
