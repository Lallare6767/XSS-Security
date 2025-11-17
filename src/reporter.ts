/**
 * Comprehensive vulnerability reporter with visual console output
 */

import { ScanResult, Vulnerability, SeverityLevel, VulnerabilityType } from './types';

export class VulnerabilityReporter {
  private readonly COLORS = {
    critical: '#ff0000',
    high: '#ff6b00',
    medium: '#ffa500',
    low: '#ffff00',
    info: '#00bfff',
    success: '#00ff00',
    header: '#9d4edd',
    text: '#ffffff',
  };

  private readonly ICONS = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢',
    info: '🔵',
    success: '✅',
    warning: '⚠️',
    error: '❌',
    shield: '🛡️',
    bug: '🐛',
    lock: '🔒',
  };

  /**
   * Generate and display comprehensive report
   */
  report(result: ScanResult): void {
    console.clear();
    this.printHeader();
    this.printSummary(result);
    this.printFrameworks(result.detectedFrameworks);

    if (result.vulnerabilities.length > 0) {
      this.printVulnerabilities(result.vulnerabilities);
      this.printRecommendations(result.vulnerabilities);
    } else {
      this.printNoVulnerabilities();
    }

    this.printFooter(result);
  }

  /**
   * Print fancy header
   */
  private printHeader(): void {
    console.log(
      '%c' + '╔══════════════════════════════════════════════════════════════╗',
      `color: ${this.COLORS.header}; font-weight: bold;`
    );
    console.log(
      '%c' + '║                                                              ║',
      `color: ${this.COLORS.header}; font-weight: bold;`
    );
    console.log(
      '%c' + '║           🛡️  XSS GUARDIAN SECURITY SCANNER 🛡️             ║',
      `color: ${this.COLORS.header}; font-weight: bold; font-size: 16px;`
    );
    console.log(
      '%c' + '║                                                              ║',
      `color: ${this.COLORS.header}; font-weight: bold;`
    );
    console.log(
      '%c' + '║     Advanced XSS Detection & Framework Analysis Tool        ║',
      `color: ${this.COLORS.header}; font-weight: bold;`
    );
    console.log(
      '%c' + '║                                                              ║',
      `color: ${this.COLORS.header}; font-weight: bold;`
    );
    console.log(
      '%c' + '╚══════════════════════════════════════════════════════════════╝',
      `color: ${this.COLORS.header}; font-weight: bold;`
    );
    console.log('');
  }

  /**
   * Print scan summary
   */
  private printSummary(result: ScanResult): void {
    console.log(
      `%c${this.ICONS.shield} SCAN SUMMARY`,
      `color: ${this.COLORS.header}; font-size: 14px; font-weight: bold;`
    );
    console.log(
      `%c${'─'.repeat(60)}`,
      `color: ${this.COLORS.header};`
    );

    const { summary } = result;
    const totalVulns = summary.total;

    console.log(
      `%cTotal Vulnerabilities Found: %c${totalVulns}`,
      'color: #ffffff; font-weight: bold;',
      totalVulns > 0 ? `color: ${this.COLORS.critical}; font-weight: bold; font-size: 18px;` : `color: ${this.COLORS.success}; font-weight: bold;`
    );

    if (totalVulns > 0) {
      console.log('');
      console.log('%cBreakdown by Severity:', 'color: #ffffff; font-weight: bold;');

      if (summary.critical > 0) {
        console.log(
          `  %c${this.ICONS.critical} CRITICAL: %c${summary.critical}`,
          `color: ${this.COLORS.critical}; font-weight: bold;`,
          `color: ${this.COLORS.critical}; font-weight: bold; font-size: 14px;`
        );
      }

      if (summary.high > 0) {
        console.log(
          `  %c${this.ICONS.high} HIGH: %c${summary.high}`,
          `color: ${this.COLORS.high}; font-weight: bold;`,
          `color: ${this.COLORS.high}; font-weight: bold; font-size: 14px;`
        );
      }

      if (summary.medium > 0) {
        console.log(
          `  %c${this.ICONS.medium} MEDIUM: %c${summary.medium}`,
          `color: ${this.COLORS.medium}; font-weight: bold;`,
          `color: ${this.COLORS.medium}; font-weight: bold;`
        );
      }

      if (summary.low > 0) {
        console.log(
          `  %c${this.ICONS.low} LOW: %c${summary.low}`,
          `color: ${this.COLORS.low}; font-weight: bold;`,
          `color: ${this.COLORS.low}; font-weight: bold;`
        );
      }

      if (summary.info > 0) {
        console.log(
          `  %c${this.ICONS.info} INFO: %c${summary.info}`,
          `color: ${this.COLORS.info}; font-weight: bold;`,
          `color: ${this.COLORS.info}; font-weight: bold;`
        );
      }
    }

    console.log('');
    console.log(
      `%cScan Duration: %c${result.scanDuration.toFixed(2)}ms`,
      'color: #ffffff;',
      'color: #00bfff; font-weight: bold;'
    );
    console.log(
      `%cTimestamp: %c${result.timestamp.toLocaleString()}`,
      'color: #ffffff;',
      'color: #00bfff;'
    );
    console.log('');
  }

  /**
   * Print detected frameworks
   */
  private printFrameworks(frameworks: string[]): void {
    if (frameworks.length === 0) return;

    console.log(
      `%c${this.ICONS.info} DETECTED FRAMEWORKS`,
      `color: ${this.COLORS.info}; font-size: 14px; font-weight: bold;`
    );
    console.log(
      `%c${'─'.repeat(60)}`,
      `color: ${this.COLORS.info};`
    );

    frameworks.forEach(framework => {
      console.log(
        `  %c✓ %c${framework.charAt(0).toUpperCase() + framework.slice(1)}`,
        'color: #00ff00; font-weight: bold;',
        'color: #ffffff;'
      );
    });

    console.log('');
  }

  /**
   * Print vulnerabilities
   */
  private printVulnerabilities(vulnerabilities: Vulnerability[]): void {
    console.log(
      `%c${this.ICONS.bug} VULNERABILITY DETAILS`,
      `color: ${this.COLORS.critical}; font-size: 14px; font-weight: bold;`
    );
    console.log(
      `%c${'═'.repeat(60)}`,
      `color: ${this.COLORS.critical};`
    );
    console.log('');

    // Group by severity
    const grouped = this.groupBySeverity(vulnerabilities);

    Object.entries(grouped).forEach(([severity, vulns]) => {
      if (vulns.length === 0) return;

      const color = this.getSeverityColor(severity as SeverityLevel);
      const icon = this.getSeverityIcon(severity as SeverityLevel);

      console.log(
        `%c${icon} ${severity} SEVERITY (${vulns.length})`,
        `color: ${color}; font-size: 13px; font-weight: bold; text-decoration: underline;`
      );
      console.log('');

      vulns.forEach((vuln, index) => {
        this.printVulnerability(vuln, index + 1, color);
        console.log('');
      });
    });
  }

  /**
   * Print single vulnerability
   */
  private printVulnerability(vuln: Vulnerability, index: number, color: string): void {
    console.log(
      `%c[${index}] %c${vuln.type}`,
      `color: ${color}; font-weight: bold;`,
      `color: ${color}; font-weight: bold; font-size: 12px;`
    );

    console.log(`%c    Description: %c${vuln.description}`, 'color: #aaaaaa;', 'color: #ffffff;');
    console.log(`%c    Sink: %c${vuln.sink}`, 'color: #aaaaaa;', 'color: #ff6b6b;');
    console.log(`%c    Source: %c${vuln.source}`, 'color: #aaaaaa;', 'color: #4ecdc4;');
    console.log(`%c    Context: %c${vuln.context}`, 'color: #aaaaaa;', 'color: #ffe66d;');

    if (vuln.framework) {
      console.log(`%c    Framework: %c${vuln.framework}`, 'color: #aaaaaa;', 'color: #a8dadc;');
    }

    if (vuln.location?.selector) {
      console.log(`%c    Selector: %c${vuln.location.selector}`, 'color: #aaaaaa;', 'color: #f1faee;');
    }

    if (vuln.element) {
      console.log(`%c    Element:`, 'color: #aaaaaa;');
      console.dir(vuln.element);
    }

    console.log(`%c    Remediation:`, `color: ${this.COLORS.success}; font-weight: bold;`);
    console.log(`%c    ${vuln.remediation}`, `color: ${this.COLORS.success};`);

    if (vuln.proofOfConcept) {
      console.log(`%c    Proof of Concept:`, 'color: #ff6b6b; font-weight: bold;');
      console.log(`%c${vuln.proofOfConcept}`, 'color: #ff6b6b; font-family: monospace;');
    }

    if (vuln.payload && vuln.payload.length < 200) {
      console.log(`%c    Payload: %c${vuln.payload}`, 'color: #aaaaaa;', 'color: #ff6b6b; font-family: monospace;');
    }
  }

  /**
   * Print recommendations
   */
  private printRecommendations(vulnerabilities: Vulnerability[]): void {
    console.log(
      `%c${this.ICONS.shield} SECURITY RECOMMENDATIONS`,
      `color: ${this.COLORS.success}; font-size: 14px; font-weight: bold;`
    );
    console.log(
      `%c${'═'.repeat(60)}`,
      `color: ${this.COLORS.success};`
    );
    console.log('');

    const recommendations = this.generateRecommendations(vulnerabilities);

    recommendations.forEach((rec, index) => {
      console.log(
        `%c${index + 1}. %c${rec}`,
        `color: ${this.COLORS.success}; font-weight: bold;`,
        `color: ${this.COLORS.text};`
      );
    });

    console.log('');
  }

  /**
   * Generate recommendations based on vulnerabilities
   */
  private generateRecommendations(vulnerabilities: Vulnerability[]): string[] {
    const recommendations: Set<string> = new Set();

    const hasInnerHTML = vulnerabilities.some(v => v.sink.includes('innerHTML'));
    const hasEval = vulnerabilities.some(v => v.sink === 'eval');
    const hasTemplateInjection = vulnerabilities.some(v => v.type === VulnerabilityType.TEMPLATE_INJECTION);
    const hasReflectedXSS = vulnerabilities.some(v => v.type === VulnerabilityType.REFLECTED_XSS);
    const hasFrameworkIssues = vulnerabilities.some(v => v.framework);

    if (hasInnerHTML) {
      recommendations.add('Use DOMPurify (https://github.com/cure53/DOMPurify) to sanitize HTML before inserting into the DOM');
      recommendations.add('Prefer textContent over innerHTML when displaying user input');
    }

    if (hasEval) {
      recommendations.add('Never use eval() or Function() constructor with user-controlled data');
      recommendations.add('Use JSON.parse() for parsing JSON instead of eval()');
    }

    if (hasTemplateInjection) {
      recommendations.add('Upgrade from legacy frameworks (AngularJS) to modern versions with better security');
      recommendations.add('Sanitize all data before rendering in template expressions');
    }

    if (hasReflectedXSS) {
      recommendations.add('Implement Content Security Policy (CSP) headers to mitigate XSS attacks');
      recommendations.add('Validate and sanitize all user input on both client and server side');
      recommendations.add('Use URL parameter allowlists instead of blocklists');
    }

    if (hasFrameworkIssues) {
      recommendations.add('Review framework-specific security best practices');
      recommendations.add('Keep frameworks and dependencies up to date');
    }

    // General recommendations
    recommendations.add('Implement HTTPOnly and Secure flags on cookies');
    recommendations.add('Use X-XSS-Protection and X-Content-Type-Options headers');
    recommendations.add('Regular security audits and penetration testing');

    return Array.from(recommendations);
  }

  /**
   * Print no vulnerabilities message
   */
  private printNoVulnerabilities(): void {
    console.log(
      `%c${this.ICONS.success} NO VULNERABILITIES DETECTED!`,
      `color: ${this.COLORS.success}; font-size: 16px; font-weight: bold;`
    );
    console.log('');
    console.log(
      '%cYour application appears to be free of common XSS vulnerabilities.',
      `color: ${this.COLORS.success};`
    );
    console.log(
      '%cHowever, always perform thorough security testing and code review.',
      'color: #ffffff;'
    );
    console.log('');
  }

  /**
   * Print footer
   */
  private printFooter(result: ScanResult): void {
    console.log(
      `%c${'═'.repeat(60)}`,
      `color: ${this.COLORS.header};`
    );
    console.log(
      '%cXSS Guardian - Protecting your application from XSS attacks',
      `color: ${this.COLORS.header}; font-style: italic;`
    );
    console.log(
      '%cFor more information and updates, visit: https://github.com/your-repo',
      'color: #00bfff;'
    );
    console.log('');
  }

  /**
   * Group vulnerabilities by severity
   */
  private groupBySeverity(vulnerabilities: Vulnerability[]): Record<SeverityLevel, Vulnerability[]> {
    const grouped: Record<SeverityLevel, Vulnerability[]> = {
      [SeverityLevel.CRITICAL]: [],
      [SeverityLevel.HIGH]: [],
      [SeverityLevel.MEDIUM]: [],
      [SeverityLevel.LOW]: [],
      [SeverityLevel.INFO]: [],
    };

    vulnerabilities.forEach(vuln => {
      grouped[vuln.severity].push(vuln);
    });

    return grouped;
  }

  /**
   * Get color for severity level
   */
  private getSeverityColor(severity: SeverityLevel): string {
    const colorMap: Record<SeverityLevel, string> = {
      [SeverityLevel.CRITICAL]: this.COLORS.critical,
      [SeverityLevel.HIGH]: this.COLORS.high,
      [SeverityLevel.MEDIUM]: this.COLORS.medium,
      [SeverityLevel.LOW]: this.COLORS.low,
      [SeverityLevel.INFO]: this.COLORS.info,
    };

    return colorMap[severity];
  }

  /**
   * Get icon for severity level
   */
  private getSeverityIcon(severity: SeverityLevel): string {
    const iconMap: Record<SeverityLevel, string> = {
      [SeverityLevel.CRITICAL]: this.ICONS.critical,
      [SeverityLevel.HIGH]: this.ICONS.high,
      [SeverityLevel.MEDIUM]: this.ICONS.medium,
      [SeverityLevel.LOW]: this.ICONS.low,
      [SeverityLevel.INFO]: this.ICONS.info,
    };

    return iconMap[severity];
  }

  /**
   * Export report as JSON
   */
  exportJSON(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }

  /**
   * Export report as HTML
   */
  exportHTML(result: ScanResult): string {
    const { summary, vulnerabilities } = result;

    let html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>XSS Guardian Security Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      padding: 20px;
      color: #333;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: white;
      border-radius: 10px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      overflow: hidden;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 40px;
      text-align: center;
    }
    .header h1 { font-size: 36px; margin-bottom: 10px; }
    .header p { font-size: 18px; opacity: 0.9; }
    .summary {
      padding: 30px 40px;
      background: #f8f9fa;
      border-bottom: 1px solid #dee2e6;
    }
    .summary h2 { margin-bottom: 20px; color: #667eea; }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 20px;
      margin-top: 20px;
    }
    .stat {
      padding: 20px;
      background: white;
      border-radius: 8px;
      text-align: center;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .stat .number {
      font-size: 32px;
      font-weight: bold;
      margin-bottom: 5px;
    }
    .stat .label {
      color: #666;
      font-size: 14px;
      text-transform: uppercase;
    }
    .critical { color: #dc3545; }
    .high { color: #fd7e14; }
    .medium { color: #ffc107; }
    .low { color: #28a745; }
    .info { color: #17a2b8; }
    .vulnerabilities {
      padding: 40px;
    }
    .vulnerability {
      margin-bottom: 30px;
      padding: 20px;
      background: #f8f9fa;
      border-left: 4px solid #667eea;
      border-radius: 4px;
    }
    .vulnerability h3 {
      margin-bottom: 10px;
      color: #333;
    }
    .vulnerability .meta {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 10px;
      margin: 15px 0;
    }
    .vulnerability .meta-item {
      font-size: 14px;
    }
    .vulnerability .meta-item strong {
      color: #667eea;
    }
    .vulnerability .remediation {
      margin-top: 15px;
      padding: 15px;
      background: #d4edda;
      border-left: 3px solid #28a745;
      border-radius: 4px;
    }
    .vulnerability .poc {
      margin-top: 15px;
      padding: 15px;
      background: #f8d7da;
      border-left: 3px solid #dc3545;
      border-radius: 4px;
      font-family: monospace;
      font-size: 12px;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ XSS Guardian Security Report</h1>
      <p>Comprehensive XSS Vulnerability Analysis</p>
      <p style="margin-top: 10px; font-size: 14px;">${result.timestamp.toLocaleString()}</p>
    </div>

    <div class="summary">
      <h2>Scan Summary</h2>
      <div class="stats">
        <div class="stat">
          <div class="number">${summary.total}</div>
          <div class="label">Total</div>
        </div>
        <div class="stat">
          <div class="number critical">${summary.critical}</div>
          <div class="label">Critical</div>
        </div>
        <div class="stat">
          <div class="number high">${summary.high}</div>
          <div class="label">High</div>
        </div>
        <div class="stat">
          <div class="number medium">${summary.medium}</div>
          <div class="label">Medium</div>
        </div>
        <div class="stat">
          <div class="number low">${summary.low}</div>
          <div class="label">Low</div>
        </div>
      </div>
    </div>

    <div class="vulnerabilities">
      <h2 style="margin-bottom: 30px; color: #667eea;">Vulnerability Details</h2>
`;

    vulnerabilities.forEach((vuln, index) => {
      const severityClass = vuln.severity.toLowerCase();

      html += `
      <div class="vulnerability">
        <h3 class="${severityClass}">[${index + 1}] ${vuln.type} - ${vuln.severity}</h3>
        <p>${vuln.description}</p>

        <div class="meta">
          <div class="meta-item"><strong>Sink:</strong> ${vuln.sink}</div>
          <div class="meta-item"><strong>Source:</strong> ${vuln.source}</div>
          <div class="meta-item"><strong>Context:</strong> ${vuln.context}</div>
          ${vuln.framework ? `<div class="meta-item"><strong>Framework:</strong> ${vuln.framework}</div>` : ''}
        </div>

        <div class="remediation">
          <strong>✅ Remediation:</strong><br>
          ${vuln.remediation}
        </div>

        ${vuln.proofOfConcept ? `
        <div class="poc">
          <strong>🔍 Proof of Concept:</strong><br>
          ${this.escapeHTML(vuln.proofOfConcept)}
        </div>
        ` : ''}
      </div>
`;
    });

    html += `
    </div>
  </div>
</body>
</html>
`;

    return html;
  }

  /**
   * Escape HTML for safe rendering
   */
  private escapeHTML(str: string): string {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  /**
   * Download report
   */
  downloadReport(result: ScanResult, format: 'json' | 'html' = 'html'): void {
    const content = format === 'json' ? this.exportJSON(result) : this.exportHTML(result);
    const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `xss-guardian-report-${Date.now()}.${format}`;
    a.click();
    URL.revokeObjectURL(url);

    console.log(`%c✅ Report downloaded as ${format.toUpperCase()}`, `color: ${this.COLORS.success}; font-weight: bold;`);
  }
}
