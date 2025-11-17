# 🛡️ XSS Guardian

> **The most sophisticated XSS detection tool for modern web applications**

XSS Guardian is an advanced, comprehensive XSS (Cross-Site Scripting) vulnerability scanner designed for security professionals, developers, and penetration testers. It provides deep analysis of DOM structures, framework-specific patterns, and uses mutation-based testing to uncover even the most subtle XSS vulnerabilities.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![Security](https://img.shields.io/badge/Security-Focused-red.svg)](https://github.com/yourusername/xss-guardian)

## ✨ Features

### 🔍 **Comprehensive Detection**
- **DOM-based XSS**: Deep inspection of DOM sinks and sources
- **Reflected XSS**: Active mutation testing with payload injection
- **Stored XSS**: Detection of dangerous storage patterns
- **Mutation XSS (mXSS)**: Advanced DOM mutation analysis
- **Prototype Pollution**: Detection of prototype chain vulnerabilities

### 🎯 **Framework-Specific Analysis**
Specialized analyzers for popular frameworks:
- **Aurelia** (innerHTML.bind, template injection)
- **React** (dangerouslySetInnerHTML, JSX patterns)
- **Vue** (v-html directive, template expressions)
- **Angular** (innerHTML binding, template injection)
- **Alpine.js** (x-html directive)
- **jQuery** (dangerous selectors and methods)
- Auto-detection for: Svelte, Next.js, Nuxt.js, Ember, Backbone, and more

### 💉 **Advanced Payload Library**
- **200+ XSS payloads** with various encoding techniques
- HTML entities (decimal & hexadecimal)
- Unicode escape sequences
- Base64 encoding
- URL encoding variations
- **WAF bypass techniques**
- **CSP bypass patterns**
- **DOM clobbering payloads**
- Framework-specific injection vectors

### 📊 **Beautiful Reporting**
- Color-coded console output with severity levels
- Detailed vulnerability descriptions
- Specific remediation advice for each finding
- Proof-of-concept code generation
- Export reports as HTML or JSON
- Downloadable security audit reports

### 🚀 **Easy Activation**
- Browser bookmarklet (one-click activation)
- Console script injection
- NPM package for CI/CD integration
- Standalone HTML page
- Chrome/Firefox extension ready

## 🎬 Quick Start

### Method 1: Bookmarklet (Easiest)

1. Visit our [bookmarklet page](./bookmarklet.html)
2. Drag the **🛡️ XSS Guardian** button to your bookmarks bar
3. Navigate to any website
4. Click the bookmarklet
5. Open console (F12) to view results

### Method 2: Browser Console

Open the browser console (F12) and paste:

```javascript
var script = document.createElement('script');
script.src = 'https://cdn.jsdelivr.net/gh/yourusername/xss-guardian@main/dist/xss-guardian.js';
script.onload = function() {
  XSSGuardian.quickScan();
};
document.head.appendChild(script);
```

### Method 3: NPM Installation

```bash
npm install xss-guardian
```

```javascript
import XSSGuardian from 'xss-guardian';

const guardian = XSSGuardian.create();
const result = await guardian.quickScan();
```

## 📖 Usage

### Quick Scan (Recommended)
```javascript
// Fast scan without mutation testing
const result = await XSSGuardian.quickScan();
```

### Deep Scan
```javascript
// Comprehensive scan with mutation testing
// ⚠️ Warning: Will temporarily modify the page
const result = await XSSGuardian.deepScan();
```

### Custom Scan
```javascript
const result = await XSSGuardian.scan({
  depth: 20,                    // DOM traversal depth
  includeShadowDOM: true,       // Scan Shadow DOM
  includeIframes: true,         // Scan iframes (same-origin only)
  mutationTest: true,           // Enable mutation testing
  payloadComplexity: 'all',     // 'basic' | 'intermediate' | 'advanced' | 'all'
  verbose: true,                // Verbose logging
  frameworks: ['react', 'vue'], // Specific frameworks to scan
});
```

### Framework-Specific Scan
```javascript
// Focus on framework-specific vulnerabilities
const result = await XSSGuardian.frameworkScan(['aurelia', 'react']);
```

### Export Reports
```javascript
// Export as HTML
XSSGuardian.exportReport(result, 'html');

// Export as JSON
XSSGuardian.exportReport(result, 'json');
```

## 🔬 What It Detects

### DOM Sinks
- `innerHTML`, `outerHTML`
- `document.write()`, `document.writeln()`
- `eval()`, `setTimeout()`, `setInterval()`
- `Function()` constructor
- Script `src`, `text`, `textContent`
- Event handlers (`onclick`, `onerror`, etc.)
- URL-based sinks (`location.href`, `iframe.src`, etc.)

### DOM Sources
- `location.hash`, `location.search`
- `document.URL`, `document.referrer`
- Form inputs (`input.value`, `textarea.value`)
- `localStorage`, `sessionStorage`
- `document.cookie`
- `postMessage` data
- WebSocket messages

### Framework-Specific Patterns

#### Aurelia
```html
<!-- Detected: Dangerous innerHTML binding -->
<div innerhtml.bind="userInput"></div>
<div innerhtml.one-time="${data}"></div>
```

#### React
```jsx
// Detected: dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />
```

#### Vue
```html
<!-- Detected: v-html directive -->
<div v-html="userInput"></div>
```

#### Angular
```html
<!-- Detected: innerHTML binding -->
<div [innerHTML]="userInput"></div>
```

#### Alpine.js
```html
<!-- Detected: x-html directive -->
<div x-html="userInput"></div>
```

## 📊 Understanding Results

### Severity Levels

- 🔴 **CRITICAL**: Confirmed exploitable XSS (payload executed)
- 🟠 **HIGH**: Likely exploitable with proper payload
- 🟡 **MEDIUM**: Potentially exploitable under certain conditions
- 🟢 **LOW**: Suspicious pattern but low exploitability
- 🔵 **INFO**: Informational finding

### Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║           🛡️  XSS GUARDIAN SECURITY SCANNER 🛡️             ║
╚══════════════════════════════════════════════════════════════╝

🛡️ SCAN SUMMARY
────────────────────────────────────────────────────────────
Total Vulnerabilities Found: 5

Breakdown by Severity:
  🔴 CRITICAL: 2
  🟠 HIGH: 2
  🟡 MEDIUM: 1

🔵 DETECTED FRAMEWORKS
────────────────────────────────────────────────────────────
  ✓ Aurelia
  ✓ React

🐛 VULNERABILITY DETAILS
════════════════════════════════════════════════════════════

🔴 CRITICAL SEVERITY (2)

[1] DOM_XSS
    Description: Event handler onclick contains user input from url.param.name
    Sink: onclick
    Source: url.param.name
    Context: javascript
    Remediation: Never use user input directly in event handlers...

    Proof of Concept:
    // User controlled: url.param.name = "<img src=x onerror=alert(1)>"
    // Reflected in: onclick="handleClick('<img src=x onerror=alert(1)>')"
```

## 🛠️ Advanced Features

### Custom Payloads

```javascript
import { PayloadLibrary } from 'xss-guardian';

// Get payloads for specific context
const htmlPayloads = PayloadLibrary.getPayloadsForContext('html', 'advanced');

// Encode custom payload
const encoded = PayloadLibrary.encodePayload('<script>alert(1)</script>', 'html-hex');
```

### Programmatic Access

```javascript
import { DOMAnalyzer, MutationTester } from 'xss-guardian';

// Use individual analyzers
const domAnalyzer = new DOMAnalyzer();
const vulnerabilities = domAnalyzer.scan({
  depth: 10,
  includeShadowDOM: true
});

// Run mutation tests
const mutationTester = new MutationTester();
const results = await mutationTester.test({
  payloadComplexity: 'advanced'
});
```

## 🔒 Security & Ethics

### Important Notice

XSS Guardian is a security testing tool intended **ONLY** for:
- ✅ Testing your own applications
- ✅ Authorized security audits and penetration tests
- ✅ Educational purposes and security research
- ✅ Bug bounty programs (with explicit permission)

### Legal Disclaimer

⚠️ **WARNING**: Unauthorized testing of websites you don't own is illegal and unethical. Always obtain proper written authorization before conducting security testing. The authors are not responsible for misuse of this tool.

### Responsible Disclosure

If you find vulnerabilities using XSS Guardian:
1. **DO NOT** exploit them maliciously
2. Report to the website owner/security team
3. Follow responsible disclosure guidelines
4. Allow reasonable time for fixes before public disclosure

## 🏗️ Development

### Build from Source

```bash
# Clone repository
git clone https://github.com/yourusername/xss-guardian.git
cd xss-guardian

# Install dependencies
npm install

# Build
npm run build

# Development mode (watch)
npm run watch
```

### Project Structure

```
xss-guardian/
├── src/
│   ├── index.ts                    # Main entry point
│   ├── xss-guardian.ts             # Core Guardian class
│   ├── types.ts                    # TypeScript definitions
│   ├── constants.ts                # Sinks, sources, patterns
│   ├── payloads.ts                 # Payload library
│   ├── reporter.ts                 # Report generation
│   └── detectors/
│       ├── dom-analyzer.ts         # DOM analysis
│       ├── mutation-tester.ts      # Mutation testing
│       └── framework-detector.ts   # Framework detection
├── examples/
│   └── basic-usage.html            # Usage examples
├── dist/                           # Compiled output
├── bookmarklet.html                # Bookmarklet page
└── README.md
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Areas for Contribution
- Additional framework analyzers
- New XSS payload techniques
- Performance improvements
- Documentation enhancements
- Bug fixes

## 📚 Resources

### XSS References
- [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [HackTricks XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)

### Framework Security
- [React Security Best Practices](https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml)
- [Vue.js Security Guide](https://vuejs.org/guide/best-practices/security.html)
- [Angular Security Guide](https://angular.io/guide/security)
- [Aurelia Security Considerations](https://aurelia.io/docs/fundamentals/security)

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

- Inspired by various XSS detection tools and research
- Thanks to the security community for XSS research and payloads
- Framework teams for security documentation

## 📧 Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/xss-guardian/issues)
- **Security**: Report vulnerabilities privately to security@example.com
- **Twitter**: [@xssguardian](https://twitter.com/xssguardian)

---

**Made with ❤️ and ☕ by security enthusiasts**

⭐ Star this repo if you find it useful!

🔐 Stay safe, scan often!
