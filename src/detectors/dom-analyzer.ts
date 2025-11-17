/**
 * Advanced DOM analyzer for detecting XSS vulnerabilities
 */

import { Vulnerability, VulnerabilityType, SeverityLevel, ScanOptions } from '../types';
import { DOM_SINKS, DOM_SOURCES, EVENT_HANDLERS, DANGEROUS_ATTRIBUTES } from '../constants';
import { PayloadLibrary } from '../payloads';

export class DOMAnalyzer {
  private vulnerabilities: Vulnerability[] = [];
  private scannedElements: WeakSet<Element> = new WeakSet();
  private sourceTracker: Map<string, any> = new Map();

  /**
   * Scan the DOM for XSS vulnerabilities
   */
  scan(options: ScanOptions = {}): Vulnerability[] {
    this.vulnerabilities = [];
    this.scannedElements = new WeakSet();
    this.sourceTracker.clear();

    console.log('🔍 Starting comprehensive DOM scan...');

    // Track all DOM sources
    this.trackDOMSources();

    // Scan document
    this.scanElement(document.documentElement, options);

    // Scan shadow DOM if requested
    if (options.includeShadowDOM) {
      this.scanShadowDOM(options);
    }

    // Scan iframes if requested
    if (options.includeIframes) {
      this.scanIframes(options);
    }

    // Detect dangerous patterns
    this.detectDangerousPatterns(options);

    // Detect event handler injections
    this.detectEventHandlerInjections(options);

    // Detect inline script patterns
    this.detectInlineScriptPatterns(options);

    // Detect DOM-based source to sink flows
    this.detectSourceToSinkFlows(options);

    return this.vulnerabilities;
  }

  /**
   * Track all DOM sources that could be attacker-controlled
   */
  private trackDOMSources(): void {
    // URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach((value, key) => {
      this.sourceTracker.set(`url.param.${key}`, value);
    });

    // Hash
    if (window.location.hash) {
      this.sourceTracker.set('url.hash', window.location.hash);
    }

    // Referrer
    if (document.referrer) {
      this.sourceTracker.set('document.referrer', document.referrer);
    }

    // LocalStorage
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key) {
        this.sourceTracker.set(`localStorage.${key}`, localStorage.getItem(key));
      }
    }

    // SessionStorage
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key) {
        this.sourceTracker.set(`sessionStorage.${key}`, sessionStorage.getItem(key));
      }
    }

    // Cookies
    document.cookie.split(';').forEach(cookie => {
      const [key, value] = cookie.trim().split('=');
      if (key && value) {
        this.sourceTracker.set(`cookie.${key}`, value);
      }
    });
  }

  /**
   * Scan a single element and its children
   */
  private scanElement(element: Element, options: ScanOptions, depth: number = 0): void {
    if (!element || this.scannedElements.has(element)) return;
    if (options.depth && depth > options.depth) return;

    this.scannedElements.add(element);

    // Check attributes for XSS vectors
    this.checkElementAttributes(element);

    // Check for dangerous event handlers
    this.checkEventHandlers(element);

    // Check for innerHTML/outerHTML usage
    this.checkHTMLContent(element);

    // Check for framework-specific patterns
    this.checkFrameworkPatterns(element, options);

    // Recursively scan children
    Array.from(element.children).forEach(child => {
      this.scanElement(child, options, depth + 1);
    });
  }

  /**
   * Check element attributes for XSS vulnerabilities
   */
  private checkElementAttributes(element: Element): void {
    DANGEROUS_ATTRIBUTES.forEach(attr => {
      const value = element.getAttribute(attr);
      if (value) {
        // Check for javascript: protocol
        if (value.trim().toLowerCase().startsWith('javascript:')) {
          this.addVulnerability({
            type: VulnerabilityType.DOM_XSS,
            severity: SeverityLevel.HIGH,
            element,
            sink: attr,
            source: 'attribute',
            context: 'url',
            payload: value,
            description: `Dangerous javascript: protocol in ${attr} attribute`,
            remediation: `Remove javascript: protocol or sanitize the ${attr} attribute value`,
            location: this.getElementLocation(element),
          });
        }

        // Check for data: protocol with script
        if (value.trim().toLowerCase().startsWith('data:') && value.includes('script')) {
          this.addVulnerability({
            type: VulnerabilityType.DOM_XSS,
            severity: SeverityLevel.HIGH,
            element,
            sink: attr,
            source: 'attribute',
            context: 'url',
            payload: value,
            description: `Dangerous data: URL with script in ${attr} attribute`,
            remediation: `Avoid using data: URLs with script content in ${attr}`,
            location: this.getElementLocation(element),
          });
        }

        // Check for event handlers with user input
        if (EVENT_HANDLERS.includes(attr.toLowerCase())) {
          this.sourceTracker.forEach((sourceValue, sourceName) => {
            if (value.includes(sourceValue)) {
              this.addVulnerability({
                type: VulnerabilityType.DOM_XSS,
                severity: SeverityLevel.CRITICAL,
                element,
                sink: attr,
                source: sourceName,
                context: 'javascript',
                payload: value,
                description: `Event handler ${attr} contains user-controlled input from ${sourceName}`,
                remediation: 'Never use user input directly in event handlers. Use addEventListener with proper sanitization.',
                location: this.getElementLocation(element),
                proofOfConcept: `// User controlled: ${sourceName} = "${sourceValue}"\n// Reflected in: ${attr}="${value}"`,
              });
            }
          });
        }

        // Check for src/href with user input
        if (['src', 'href', 'action', 'formaction'].includes(attr.toLowerCase())) {
          this.sourceTracker.forEach((sourceValue, sourceName) => {
            if (value.includes(sourceValue)) {
              this.addVulnerability({
                type: VulnerabilityType.DOM_XSS,
                severity: SeverityLevel.HIGH,
                element,
                sink: attr,
                source: sourceName,
                context: 'url',
                payload: value,
                description: `${attr} attribute contains user-controlled input from ${sourceName}`,
                remediation: `Validate and sanitize ${sourceName} before using in ${attr}. Use allowlist for URLs.`,
                location: this.getElementLocation(element),
                proofOfConcept: `// User controlled: ${sourceName} = "${sourceValue}"\n// Reflected in: ${attr}="${value}"`,
              });
            }
          });
        }
      }
    });
  }

  /**
   * Check for dangerous event handlers
   */
  private checkEventHandlers(element: Element): void {
    EVENT_HANDLERS.forEach(handler => {
      const prop = handler.replace('on', '');
      const handlerFunc = (element as any)[handler];

      if (handlerFunc && typeof handlerFunc === 'function') {
        const handlerString = handlerFunc.toString();

        // Check if handler uses eval or Function constructor
        if (handlerString.includes('eval(') || handlerString.includes('Function(')) {
          this.addVulnerability({
            type: VulnerabilityType.DOM_XSS,
            severity: SeverityLevel.CRITICAL,
            element,
            sink: handler,
            source: 'event-handler',
            context: 'javascript',
            payload: handlerString,
            description: `Event handler ${handler} uses dangerous eval() or Function()`,
            remediation: 'Never use eval() or Function() constructor with user input',
            location: this.getElementLocation(element),
          });
        }

        // Check for user-controlled input in handler
        this.sourceTracker.forEach((sourceValue, sourceName) => {
          if (handlerString.includes(sourceValue)) {
            this.addVulnerability({
              type: VulnerabilityType.DOM_XSS,
              severity: SeverityLevel.HIGH,
              element,
              sink: handler,
              source: sourceName,
              context: 'javascript',
              payload: handlerString,
              description: `Event handler ${handler} contains user-controlled input from ${sourceName}`,
              remediation: 'Sanitize user input before using in event handlers',
              location: this.getElementLocation(element),
            });
          }
        });
      }
    });
  }

  /**
   * Check for dangerous HTML content
   */
  private checkHTMLContent(element: Element): void {
    const innerHTML = element.innerHTML;
    const outerHTML = element.outerHTML;

    // Check if innerHTML contains user input
    this.sourceTracker.forEach((sourceValue, sourceName) => {
      if (innerHTML.includes(sourceValue) && sourceValue.length > 3) {
        // Check if it's part of a script or dangerous tag
        const scriptMatch = innerHTML.match(new RegExp(`<script[^>]*>${sourceValue}`, 'i'));
        const dangerousMatch = innerHTML.match(new RegExp(`<[^>]*(onerror|onload)[^>]*=${sourceValue}`, 'i'));

        if (scriptMatch || dangerousMatch) {
          this.addVulnerability({
            type: VulnerabilityType.DOM_XSS,
            severity: SeverityLevel.CRITICAL,
            element,
            sink: 'innerHTML',
            source: sourceName,
            context: 'html',
            payload: sourceValue,
            description: `User-controlled input from ${sourceName} reflected in dangerous HTML context`,
            remediation: 'Use textContent instead of innerHTML, or sanitize with DOMPurify',
            location: this.getElementLocation(element),
            proofOfConcept: `// Source: ${sourceName} = "${sourceValue}"\n// Sink: innerHTML contains dangerous content`,
          });
        }
      }
    });
  }

  /**
   * Check for framework-specific XSS patterns
   */
  private checkFrameworkPatterns(element: Element, options: ScanOptions): void {
    // Aurelia
    if (element.hasAttribute('innerhtml.bind') || element.hasAttribute('innerhtml.one-time')) {
      const binding = element.getAttribute('innerhtml.bind') || element.getAttribute('innerhtml.one-time');
      this.addVulnerability({
        type: VulnerabilityType.DOM_XSS,
        severity: SeverityLevel.HIGH,
        element,
        sink: 'innerhtml.bind',
        source: 'aurelia-binding',
        context: 'html',
        payload: binding || '',
        description: 'Aurelia innerHTML binding detected - potentially dangerous',
        remediation: 'Use sanitized-html or textContent binding instead',
        framework: 'Aurelia',
        location: this.getElementLocation(element),
      });
    }

    // Vue v-html
    if (element.hasAttribute('v-html')) {
      const binding = element.getAttribute('v-html');
      this.addVulnerability({
        type: VulnerabilityType.DOM_XSS,
        severity: SeverityLevel.HIGH,
        element,
        sink: 'v-html',
        source: 'vue-binding',
        context: 'html',
        payload: binding || '',
        description: 'Vue v-html directive detected - potentially dangerous',
        remediation: 'Sanitize data before using v-html or use v-text instead',
        framework: 'Vue',
        location: this.getElementLocation(element),
      });
    }

    // Alpine.js x-html
    if (element.hasAttribute('x-html')) {
      const binding = element.getAttribute('x-html');
      this.addVulnerability({
        type: VulnerabilityType.DOM_XSS,
        severity: SeverityLevel.HIGH,
        element,
        sink: 'x-html',
        source: 'alpine-binding',
        context: 'html',
        payload: binding || '',
        description: 'Alpine.js x-html directive detected - potentially dangerous',
        remediation: 'Sanitize data before using x-html or use x-text instead',
        framework: 'Alpine.js',
        location: this.getElementLocation(element),
      });
    }

    // React dangerouslySetInnerHTML (check in comments for JSX)
    const elementHTML = element.outerHTML;
    if (elementHTML.includes('dangerouslySetInnerHTML')) {
      this.addVulnerability({
        type: VulnerabilityType.DOM_XSS,
        severity: SeverityLevel.HIGH,
        element,
        sink: 'dangerouslySetInnerHTML',
        source: 'react-prop',
        context: 'html',
        payload: '',
        description: 'React dangerouslySetInnerHTML detected - potentially dangerous',
        remediation: 'Sanitize HTML before using dangerouslySetInnerHTML or avoid it entirely',
        framework: 'React',
        location: this.getElementLocation(element),
      });
    }
  }

  /**
   * Detect dangerous patterns in scripts
   */
  private detectDangerousPatterns(options: ScanOptions): void {
    const scripts = document.querySelectorAll('script');

    scripts.forEach(script => {
      const content = script.textContent || '';

      // Check for eval usage
      if (content.includes('eval(')) {
        const evalMatches = content.match(/eval\([^)]+\)/g);
        evalMatches?.forEach(match => {
          this.addVulnerability({
            type: VulnerabilityType.DOM_XSS,
            severity: SeverityLevel.HIGH,
            element: script,
            sink: 'eval',
            source: 'script',
            context: 'javascript',
            payload: match,
            description: 'Usage of eval() detected - extremely dangerous',
            remediation: 'Avoid using eval(). Use JSON.parse() for JSON or proper alternatives',
            location: this.getElementLocation(script),
          });
        });
      }

      // Check for Function constructor
      if (content.match(/new\s+Function\(/)) {
        this.addVulnerability({
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.HIGH,
          element: script,
          sink: 'Function',
          source: 'script',
          context: 'javascript',
          payload: content,
          description: 'Usage of Function() constructor detected',
          remediation: 'Avoid dynamic code generation with Function()',
          location: this.getElementLocation(script),
        });
      }

      // Check for setTimeout/setInterval with string
      const timeoutMatch = content.match(/set(Timeout|Interval)\s*\(\s*['"`][^'"`]+['"`]/g);
      if (timeoutMatch) {
        this.addVulnerability({
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.MEDIUM,
          element: script,
          sink: 'setTimeout/setInterval',
          source: 'script',
          context: 'javascript',
          payload: timeoutMatch.join(', '),
          description: 'setTimeout/setInterval with string argument detected',
          remediation: 'Use function references instead of strings',
          location: this.getElementLocation(script),
        });
      }

      // Check for innerHTML assignment
      const innerHTMLMatch = content.match(/\.innerHTML\s*=\s*[^;]+/g);
      innerHTMLMatch?.forEach(match => {
        this.sourceTracker.forEach((sourceValue, sourceName) => {
          if (match.includes(sourceName) || match.includes('location.') || match.includes('document.URL')) {
            this.addVulnerability({
              type: VulnerabilityType.DOM_XSS,
              severity: SeverityLevel.CRITICAL,
              element: script,
              sink: 'innerHTML',
              source: sourceName,
              context: 'html',
              payload: match,
              description: `innerHTML assignment with user-controlled data from ${sourceName}`,
              remediation: 'Use textContent or DOMPurify.sanitize()',
              location: this.getElementLocation(script),
              proofOfConcept: `// Dangerous pattern:\n${match}`,
            });
          }
        });
      });

      // Check for document.write
      if (content.includes('document.write')) {
        this.addVulnerability({
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.MEDIUM,
          element: script,
          sink: 'document.write',
          source: 'script',
          context: 'html',
          payload: content,
          description: 'Usage of document.write() detected',
          remediation: 'Use modern DOM manipulation methods instead',
          location: this.getElementLocation(script),
        });
      }
    });
  }

  /**
   * Detect event handler injections
   */
  private detectEventHandlerInjections(options: ScanOptions): void {
    const allElements = document.querySelectorAll('*');

    allElements.forEach(element => {
      EVENT_HANDLERS.forEach(handler => {
        const attrValue = element.getAttribute(handler);
        if (attrValue) {
          // Check if it contains user input
          this.sourceTracker.forEach((sourceValue, sourceName) => {
            if (attrValue.includes(sourceValue)) {
              this.addVulnerability({
                type: VulnerabilityType.DOM_XSS,
                severity: SeverityLevel.CRITICAL,
                element,
                sink: handler,
                source: sourceName,
                context: 'javascript',
                payload: attrValue,
                description: `Event handler ${handler} contains user input from ${sourceName}`,
                remediation: 'Never place user input in event handlers. Use addEventListener instead.',
                location: this.getElementLocation(element),
                proofOfConcept: `<${element.tagName.toLowerCase()} ${handler}="${attrValue}">`,
              });
            }
          });
        }
      });
    });
  }

  /**
   * Detect inline script patterns that use user input
   */
  private detectInlineScriptPatterns(options: ScanOptions): void {
    const scripts = document.querySelectorAll('script:not([src])');

    scripts.forEach(script => {
      const content = script.textContent || '';

      // Check for common DOM source patterns
      const patterns = [
        /location\.hash/g,
        /location\.search/g,
        /location\.href/g,
        /document\.URL/g,
        /document\.referrer/g,
        /window\.name/g,
        /localStorage\./g,
        /sessionStorage\./g,
      ];

      patterns.forEach(pattern => {
        if (pattern.test(content)) {
          const match = content.match(pattern);
          if (match) {
            this.addVulnerability({
              type: VulnerabilityType.DOM_XSS,
              severity: SeverityLevel.HIGH,
              element: script,
              sink: 'user-controlled-source',
              source: match[0],
              context: 'javascript',
              payload: content,
              description: `Script uses potentially attacker-controlled source: ${match[0]}`,
              remediation: 'Sanitize all user-controlled input before using in DOM manipulation',
              location: this.getElementLocation(script),
            });
          }
        }
      });
    });
  }

  /**
   * Detect source-to-sink data flows
   */
  private detectSourceToSinkFlows(options: ScanOptions): void {
    // This is a simplified version - a real implementation would use
    // more sophisticated taint tracking
    const scripts = document.querySelectorAll('script:not([src])');

    scripts.forEach(script => {
      const content = script.textContent || '';

      // Check for flows from location to innerHTML
      if (content.includes('location.') && content.includes('innerHTML')) {
        this.addVulnerability({
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.CRITICAL,
          element: script,
          sink: 'innerHTML',
          source: 'location',
          context: 'html',
          payload: content,
          description: 'Data flow from location (source) to innerHTML (sink) detected',
          remediation: 'Sanitize location data before assigning to innerHTML',
          location: this.getElementLocation(script),
        });
      }

      // Check for flows from location to eval
      if (content.includes('location.') && content.includes('eval(')) {
        this.addVulnerability({
          type: VulnerabilityType.DOM_XSS,
          severity: SeverityLevel.CRITICAL,
          element: script,
          sink: 'eval',
          source: 'location',
          context: 'javascript',
          payload: content,
          description: 'Data flow from location (source) to eval (sink) detected',
          remediation: 'Never use eval with user-controlled data',
          location: this.getElementLocation(script),
        });
      }
    });
  }

  /**
   * Scan shadow DOM
   */
  private scanShadowDOM(options: ScanOptions): void {
    const elementsWithShadow = document.querySelectorAll('*');
    elementsWithShadow.forEach(element => {
      if (element.shadowRoot) {
        console.log('🔍 Scanning Shadow DOM...');
        this.scanElement(element.shadowRoot as any, options);
      }
    });
  }

  /**
   * Scan iframes
   */
  private scanIframes(options: ScanOptions): void {
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
      try {
        if (iframe.contentDocument) {
          console.log('🔍 Scanning iframe...');
          this.scanElement(iframe.contentDocument.documentElement, options);
        }
      } catch (e) {
        // Cross-origin iframe, can't access
        console.warn('Cannot scan cross-origin iframe');
      }
    });
  }

  /**
   * Get element location information
   */
  private getElementLocation(element: Element): any {
    const selector = this.generateSelector(element);
    const xpath = this.generateXPath(element);

    return {
      selector,
      xpath,
    };
  }

  /**
   * Generate CSS selector for element
   */
  private generateSelector(element: Element): string {
    if (element.id) {
      return `#${element.id}`;
    }

    let path = [];
    let current: Element | null = element;

    while (current && current !== document.documentElement) {
      let selector = current.tagName.toLowerCase();

      if (current.className) {
        const classes = current.className.split(' ').filter(c => c).join('.');
        if (classes) selector += `.${classes}`;
      }

      path.unshift(selector);
      current = current.parentElement;
    }

    return path.join(' > ');
  }

  /**
   * Generate XPath for element
   */
  private generateXPath(element: Element): string {
    if (element.id) {
      return `//*[@id="${element.id}"]`;
    }

    let path = [];
    let current: Element | null = element;

    while (current && current !== document.documentElement) {
      let index = 1;
      let sibling = current.previousElementSibling;

      while (sibling) {
        if (sibling.tagName === current.tagName) {
          index++;
        }
        sibling = sibling.previousElementSibling;
      }

      path.unshift(`${current.tagName.toLowerCase()}[${index}]`);
      current = current.parentElement;
    }

    return '/' + path.join('/');
  }

  /**
   * Add vulnerability to the list
   */
  private addVulnerability(vuln: Omit<Vulnerability, 'id'>): void {
    const id = `${vuln.type}-${vuln.sink}-${Date.now()}-${Math.random()}`;
    this.vulnerabilities.push({ ...vuln, id });
  }
}
