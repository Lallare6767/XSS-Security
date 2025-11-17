/**
 * Framework detection and analysis
 */

import { FrameworkDetector, Vulnerability, VulnerabilityType, SeverityLevel, ScanOptions } from '../types';
import { FRAMEWORK_PATTERNS } from '../constants';

export class FrameworkDetectionService {
  private detectedFrameworks: Map<string, string | null> = new Map();

  /**
   * Detect all frameworks used on the page
   */
  detectFrameworks(): string[] {
    this.detectedFrameworks.clear();

    Object.entries(FRAMEWORK_PATTERNS).forEach(([name, pattern]) => {
      if (pattern.globalCheck()) {
        const version = this.getFrameworkVersion(name);
        this.detectedFrameworks.set(name, version);
        console.log(`✓ Detected ${name}${version ? ` v${version}` : ''}`);
      }
    });

    // Check for additional frameworks
    this.checkAdditionalFrameworks();

    return Array.from(this.detectedFrameworks.keys());
  }

  /**
   * Check for additional frameworks not in FRAMEWORK_PATTERNS
   */
  private checkAdditionalFrameworks(): void {
    // Ember.js
    if ((window as any).Ember) {
      this.detectedFrameworks.set('ember', (window as any).Ember.VERSION);
    }

    // Backbone.js
    if ((window as any).Backbone) {
      this.detectedFrameworks.set('backbone', (window as any).Backbone.VERSION);
    }

    // Next.js
    if ((window as any).__NEXT_DATA__) {
      this.detectedFrameworks.set('next', null);
    }

    // Nuxt.js
    if ((window as any).__NUXT__) {
      this.detectedFrameworks.set('nuxt', null);
    }

    // Gatsby
    if ((window as any).___gatsby) {
      this.detectedFrameworks.set('gatsby', null);
    }

    // Polymer
    if ((window as any).Polymer) {
      this.detectedFrameworks.set('polymer', (window as any).Polymer.version);
    }

    // Lit
    if (document.querySelector('[data-lit]')) {
      this.detectedFrameworks.set('lit', null);
    }
  }

  /**
   * Get framework version
   */
  private getFrameworkVersion(framework: string): string | null {
    try {
      switch (framework) {
        case 'react':
          return (window as any).React?.version || null;
        case 'vue':
          return (window as any).Vue?.version || this.getVue3Version();
        case 'angular':
          return this.getAngularVersion();
        case 'jquery':
          return (window as any).jQuery?.fn?.jquery || null;
        default:
          return null;
      }
    } catch (e) {
      return null;
    }
  }

  /**
   * Get Vue 3 version from DOM
   */
  private getVue3Version(): string | null {
    const versionAttr = document.querySelector('[data-v-app]');
    return versionAttr?.getAttribute('data-v-app') || null;
  }

  /**
   * Get Angular version from DOM
   */
  private getAngularVersion(): string | null {
    const ngVersion = document.querySelector('[ng-version]');
    return ngVersion?.getAttribute('ng-version') || null;
  }

  /**
   * Get detected frameworks
   */
  getDetectedFrameworks(): Map<string, string | null> {
    return this.detectedFrameworks;
  }
}

/**
 * Aurelia-specific XSS analyzer
 */
export class AureliaAnalyzer implements FrameworkDetector {
  name = 'Aurelia';

  detect(): boolean {
    return !!(window as any).au || !!document.querySelector('[au-target-id], [aurelia-app]');
  }

  version(): string | null {
    return (window as any).au?.version || null;
  }

  sinks = [
    { property: 'innerhtml.bind', object: 'Aurelia', dangerous: true, requiresUserInteraction: false, context: 'html' as const },
    { property: 'innerhtml.one-time', object: 'Aurelia', dangerous: true, requiresUserInteraction: false, context: 'html' as const },
    { property: 'innerhtml.to-view', object: 'Aurelia', dangerous: true, requiresUserInteraction: false, context: 'html' as const },
  ];

  sources = [];

  scan(options: ScanOptions): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for innerHTML bindings
    const innerHTMLBindings = document.querySelectorAll('[innerhtml.bind], [innerhtml.one-time], [innerhtml.to-view]');

    innerHTMLBindings.forEach(element => {
      const binding = element.getAttribute('innerhtml.bind') ||
                     element.getAttribute('innerhtml.one-time') ||
                     element.getAttribute('innerhtml.to-view');

      if (binding) {
        vulnerabilities.push({
          id: `aurelia-innerhtml-${Date.now()}-${Math.random()}`,
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.HIGH,
          element,
          sink: 'innerhtml.bind',
          source: 'aurelia-binding',
          context: 'html',
          payload: binding,
          description: `Aurelia innerHTML binding detected with expression: ${binding}`,
          remediation: 'Use textContent binding or sanitize HTML with a library like DOMPurify before binding',
          framework: 'Aurelia',
          location: {
            selector: this.getSelector(element),
          },
          proofOfConcept: `<!-- Vulnerable Aurelia binding -->\n<div innerhtml.bind="${binding}"></div>\n\n// If user input reaches this binding, XSS is possible`,
        });
      }
    });

    // Check for string interpolation that might be dangerous
    const stringInterpolation = document.querySelectorAll('[textcontent.bind*="${"], [innerhtml.bind*="${"]');

    stringInterpolation.forEach(element => {
      const binding = element.getAttribute('innerhtml.bind') || element.getAttribute('textcontent.bind');

      if (binding?.includes('${')) {
        vulnerabilities.push({
          id: `aurelia-interpolation-${Date.now()}-${Math.random()}`,
          type: VulnerabilityType.TEMPLATE_INJECTION,
          severity: SeverityLevel.MEDIUM,
          element,
          sink: 'template-interpolation',
          source: 'aurelia-binding',
          context: 'html',
          payload: binding,
          description: `Aurelia template interpolation detected: ${binding}`,
          remediation: 'Ensure user input is properly escaped in template expressions',
          framework: 'Aurelia',
          location: {
            selector: this.getSelector(element),
          },
        });
      }
    });

    // Check for event binding with potential XSS
    const eventBindings = document.querySelectorAll('[click.delegate], [click.trigger], [submit.delegate]');

    eventBindings.forEach(element => {
      const clickBinding = element.getAttribute('click.delegate') ||
                          element.getAttribute('click.trigger') ||
                          element.getAttribute('submit.delegate');

      if (clickBinding?.includes('eval') || clickBinding?.includes('Function')) {
        vulnerabilities.push({
          id: `aurelia-event-${Date.now()}-${Math.random()}`,
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.HIGH,
          element,
          sink: 'event-binding',
          source: 'aurelia-binding',
          context: 'javascript',
          payload: clickBinding,
          description: `Dangerous Aurelia event binding with eval/Function: ${clickBinding}`,
          remediation: 'Never use eval() or Function() in event bindings',
          framework: 'Aurelia',
          location: {
            selector: this.getSelector(element),
          },
        });
      }
    });

    return vulnerabilities;
  }

  private getSelector(element: Element): string {
    return element.id ? `#${element.id}` : element.tagName.toLowerCase();
  }
}

/**
 * React-specific XSS analyzer
 */
export class ReactAnalyzer implements FrameworkDetector {
  name = 'React';

  detect(): boolean {
    return !!(window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
           !!(window as any).React ||
           !!document.querySelector('[data-reactroot], [data-reactid]');
  }

  version(): string | null {
    return (window as any).React?.version || null;
  }

  sinks = [
    { property: 'dangerouslySetInnerHTML', object: 'React', dangerous: true, requiresUserInteraction: false, context: 'html' as const },
  ];

  sources = [];

  scan(options: ScanOptions): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for dangerouslySetInnerHTML in scripts (JSX source)
    const scripts = document.querySelectorAll('script');

    scripts.forEach(script => {
      const content = script.textContent || '';

      if (content.includes('dangerouslySetInnerHTML')) {
        const matches = content.match(/dangerouslySetInnerHTML\s*=\s*\{\s*\{?\s*__html:\s*([^}]+)\}/g);

        matches?.forEach(match => {
          vulnerabilities.push({
            id: `react-dangerous-${Date.now()}-${Math.random()}`,
            type: VulnerabilityType.DOM_XSS,
            severity: SeverityLevel.HIGH,
            element: script,
            sink: 'dangerouslySetInnerHTML',
            source: 'react-prop',
            context: 'html',
            payload: match,
            description: 'React dangerouslySetInnerHTML usage detected',
            remediation: 'Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML, or avoid it entirely',
            framework: 'React',
            location: {
              selector: 'script',
            },
            proofOfConcept: `// Dangerous React pattern:\n${match}\n\n// Safe alternative:\nimport DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}} />`,
          });
        });
      }

      // Check for href={javascript:...}
      if (content.match(/href\s*=\s*\{?\s*["`']javascript:/i)) {
        vulnerabilities.push({
          id: `react-href-${Date.now()}-${Math.random()}`,
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.HIGH,
          element: script,
          sink: 'href',
          source: 'react-prop',
          context: 'url',
          payload: 'javascript:',
          description: 'React component with javascript: href detected',
          remediation: 'Never use javascript: protocol in href. Use onClick handlers instead.',
          framework: 'React',
          location: {
            selector: 'script',
          },
        });
      }
    });

    // Check for React components with innerHTML
    const reactRoots = document.querySelectorAll('[data-reactroot]');

    reactRoots.forEach(root => {
      const scripts = root.querySelectorAll('script');
      scripts.forEach(script => {
        if (script.textContent?.includes('.innerHTML')) {
          vulnerabilities.push({
            id: `react-innerhtml-${Date.now()}-${Math.random()}`,
            type: VulnerabilityType.DOM_XSS,
            severity: SeverityLevel.MEDIUM,
            element: script,
            sink: 'innerHTML',
            source: 'react-component',
            context: 'html',
            payload: script.textContent,
            description: 'React component using innerHTML directly',
            remediation: 'Use React\'s built-in rendering or dangerouslySetInnerHTML with sanitization',
            framework: 'React',
            location: {
              selector: this.getSelector(script),
            },
          });
        }
      });
    });

    return vulnerabilities;
  }

  private getSelector(element: Element): string {
    return element.id ? `#${element.id}` : element.tagName.toLowerCase();
  }
}

/**
 * Vue-specific XSS analyzer
 */
export class VueAnalyzer implements FrameworkDetector {
  name = 'Vue';

  detect(): boolean {
    return !!(window as any).Vue || !!document.querySelector('[data-v-]');
  }

  version(): string | null {
    return (window as any).Vue?.version || null;
  }

  sinks = [
    { property: 'v-html', object: 'Vue', dangerous: true, requiresUserInteraction: false, context: 'html' as const },
  ];

  sources = [];

  scan(options: ScanOptions): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for v-html directive
    const vHtmlElements = document.querySelectorAll('[v-html]');

    vHtmlElements.forEach(element => {
      const binding = element.getAttribute('v-html');

      if (binding) {
        vulnerabilities.push({
          id: `vue-vhtml-${Date.now()}-${Math.random()}`,
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.HIGH,
          element,
          sink: 'v-html',
          source: 'vue-directive',
          context: 'html',
          payload: binding,
          description: `Vue v-html directive detected with expression: ${binding}`,
          remediation: 'Use v-text for plain text or sanitize HTML with DOMPurify before using v-html',
          framework: 'Vue',
          location: {
            selector: this.getSelector(element),
          },
          proofOfConcept: `<!-- Vulnerable Vue binding -->\n<div v-html="${binding}"></div>\n\n<!-- Safe alternative -->\n<div v-text="${binding}"></div>\n<!-- OR -->\n<div v-html="$sanitize(${binding})"></div>`,
        });
      }
    });

    // Check for template interpolation with dangerous content
    const vBindElements = document.querySelectorAll('[v-bind:href], [:href], [v-bind:src], [:src]');

    vBindElements.forEach(element => {
      const href = element.getAttribute('v-bind:href') || element.getAttribute(':href');
      const src = element.getAttribute('v-bind:src') || element.getAttribute(':src');
      const binding = href || src;
      const attr = href ? 'href' : 'src';

      if (binding?.includes('javascript:')) {
        vulnerabilities.push({
          id: `vue-url-${Date.now()}-${Math.random()}`,
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.HIGH,
          element,
          sink: attr,
          source: 'vue-directive',
          context: 'url',
          payload: binding,
          description: `Vue v-bind:${attr} with javascript: protocol`,
          remediation: `Validate URL before binding to ${attr}`,
          framework: 'Vue',
          location: {
            selector: this.getSelector(element),
          },
        });
      }
    });

    return vulnerabilities;
  }

  private getSelector(element: Element): string {
    return element.id ? `#${element.id}` : element.tagName.toLowerCase();
  }
}

/**
 * Angular-specific XSS analyzer
 */
export class AngularAnalyzer implements FrameworkDetector {
  name = 'Angular';

  detect(): boolean {
    return !!(window as any).ng || !!document.querySelector('[ng-version], [ng-app]');
  }

  version(): string | null {
    const ngVersion = document.querySelector('[ng-version]');
    return ngVersion?.getAttribute('ng-version') || null;
  }

  sinks = [
    { property: 'bypassSecurityTrustHtml', object: 'Angular', dangerous: true, requiresUserInteraction: false, context: 'html' as const },
    { property: 'bypassSecurityTrustScript', object: 'Angular', dangerous: true, requiresUserInteraction: false, context: 'javascript' as const },
    { property: 'bypassSecurityTrustUrl', object: 'Angular', dangerous: true, requiresUserInteraction: false, context: 'url' as const },
  ];

  sources = [];

  scan(options: ScanOptions): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for innerHTML binding
    const innerHTMLBindings = document.querySelectorAll('[innerHTML]');

    innerHTMLBindings.forEach(element => {
      const binding = element.getAttribute('innerHTML');

      if (binding) {
        vulnerabilities.push({
          id: `angular-innerhtml-${Date.now()}-${Math.random()}`,
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.HIGH,
          element,
          sink: 'innerHTML',
          source: 'angular-binding',
          context: 'html',
          payload: binding,
          description: `Angular innerHTML binding detected: ${binding}`,
          remediation: 'Ensure HTML is sanitized. Angular sanitizes by default, but bypass methods are dangerous.',
          framework: 'Angular',
          location: {
            selector: this.getSelector(element),
          },
        });
      }
    });

    // Check for template expressions (legacy AngularJS)
    const bodyHTML = document.body.innerHTML;
    const templateExpressions = bodyHTML.match(/\{\{[^}]+\}\}/g);

    if (templateExpressions) {
      templateExpressions.forEach(expr => {
        if (expr.includes('constructor') || expr.includes('$on')) {
          vulnerabilities.push({
            id: `angular-template-${Date.now()}-${Math.random()}`,
            type: VulnerabilityType.TEMPLATE_INJECTION,
            severity: SeverityLevel.CRITICAL,
            element: null,
            sink: 'template-expression',
            source: 'angularjs-template',
            context: 'javascript',
            payload: expr,
            description: `Dangerous AngularJS template expression: ${expr}`,
            remediation: 'Upgrade from AngularJS to Angular, or sanitize template expressions',
            framework: 'AngularJS',
            location: {
              selector: 'body',
            },
            proofOfConcept: `// AngularJS template injection:\n${expr}\n\n// Example exploit:\n{{constructor.constructor('alert(1)')()}}`,
          });
        }
      });
    }

    return vulnerabilities;
  }

  private getSelector(element: Element): string {
    return element.id ? `#${element.id}` : element.tagName.toLowerCase();
  }
}

/**
 * Alpine.js-specific XSS analyzer
 */
export class AlpineAnalyzer implements FrameworkDetector {
  name = 'Alpine.js';

  detect(): boolean {
    return !!(window as any).Alpine || !!document.querySelector('[x-data]');
  }

  version(): string | null {
    return (window as any).Alpine?.version || null;
  }

  sinks = [
    { property: 'x-html', object: 'Alpine', dangerous: true, requiresUserInteraction: false, context: 'html' as const },
  ];

  sources = [];

  scan(options: ScanOptions): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for x-html directive
    const xHtmlElements = document.querySelectorAll('[x-html]');

    xHtmlElements.forEach(element => {
      const binding = element.getAttribute('x-html');

      if (binding) {
        vulnerabilities.push({
          id: `alpine-xhtml-${Date.now()}-${Math.random()}`,
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.HIGH,
          element,
          sink: 'x-html',
          source: 'alpine-directive',
          context: 'html',
          payload: binding,
          description: `Alpine.js x-html directive detected: ${binding}`,
          remediation: 'Use x-text for plain text or sanitize HTML before using x-html',
          framework: 'Alpine.js',
          location: {
            selector: this.getSelector(element),
          },
        });
      }
    });

    return vulnerabilities;
  }

  private getSelector(element: Element): string {
    return element.id ? `#${element.id}` : element.tagName.toLowerCase();
  }
}
