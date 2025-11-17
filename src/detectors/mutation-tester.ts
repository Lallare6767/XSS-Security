/**
 * Mutation-based XSS tester that actively tests for reflected XSS
 * by injecting payloads and monitoring for execution
 */

import { Vulnerability, VulnerabilityType, SeverityLevel, ScanOptions } from '../types';
import { PayloadLibrary } from '../payloads';

export class MutationTester {
  private vulnerabilities: Vulnerability[] = [];
  private testMarker = `__XSS_TEST_${Date.now()}__`;
  private executedPayloads: Set<string> = new Set();

  /**
   * Test for reflected XSS by mutating inputs and URL parameters
   */
  async test(options: ScanOptions = {}): Promise<Vulnerability[]> {
    this.vulnerabilities = [];
    this.executedPayloads.clear();

    console.log('🧪 Starting mutation-based XSS testing...');

    // Set up execution detection
    this.setupExecutionDetection();

    // Test URL parameters
    await this.testURLParameters(options);

    // Test form inputs
    await this.testFormInputs(options);

    // Test hash fragments
    await this.testHashFragments(options);

    // Test localStorage/sessionStorage
    await this.testStorageAPIs(options);

    // Test postMessage
    await this.testPostMessage(options);

    // Test DOM mutations
    await this.testDOMMutations(options);

    return this.vulnerabilities;
  }

  /**
   * Setup detection for payload execution
   */
  private setupExecutionDetection(): void {
    // Override alert to detect execution
    const originalAlert = window.alert;
    (window as any).alert = (message?: any) => {
      const msg = message?.toString() || '';
      if (msg.includes(this.testMarker) || msg === '1' || msg === 'XSS') {
        console.warn('🚨 XSS Payload executed via alert()!');
        this.executedPayloads.add(msg);
      }
      // Don't actually show the alert during testing
      if (!msg.includes(this.testMarker)) {
        originalAlert.call(window, message);
      }
    };

    // Monitor for script executions
    const originalCreateElement = document.createElement;
    document.createElement = function(tagName: string, options?: ElementCreationOptions) {
      const element = originalCreateElement.call(document, tagName, options);
      if (tagName.toLowerCase() === 'script') {
        console.warn('🚨 Script element created dynamically');
      }
      return element;
    } as any;

    // Monitor console for errors that might indicate XSS
    const originalError = console.error;
    console.error = (...args: any[]) => {
      const message = args.join(' ');
      if (message.includes(this.testMarker)) {
        console.warn('🚨 XSS marker found in console error');
      }
      originalError.apply(console, args);
    };
  }

  /**
   * Test URL parameters for reflected XSS
   */
  private async testURLParameters(options: ScanOptions): Promise<void> {
    const url = new URL(window.location.href);
    const params = new URLSearchParams(url.search);

    console.log(`🔍 Testing ${params.size} URL parameters...`);

    const payloads = PayloadLibrary.getPayloads(options.payloadComplexity || 'all');

    for (const [key, value] of params.entries()) {
      // Test each payload
      for (const payloadConfig of payloads.slice(0, 20)) { // Limit for safety
        await this.testReflection({
          location: 'url-parameter',
          paramName: key,
          originalValue: value,
          payload: payloadConfig.payload,
          payloadDescription: payloadConfig.description,
          context: payloadConfig.contexts[0],
        });

        // Small delay to prevent overwhelming the page
        await this.sleep(50);
      }
    }
  }

  /**
   * Test form inputs for reflected XSS
   */
  private async testFormInputs(options: ScanOptions): Promise<void> {
    const inputs = document.querySelectorAll('input, textarea, select');
    console.log(`🔍 Testing ${inputs.length} form inputs...`);

    const payloads = PayloadLibrary.getPayloads(options.payloadComplexity || 'intermediate');

    for (const input of Array.from(inputs)) {
      const element = input as HTMLInputElement;
      const originalValue = element.value;

      // Test each payload
      for (const payloadConfig of payloads.slice(0, 10)) { // Limit for safety
        element.value = payloadConfig.payload;

        // Trigger change event
        element.dispatchEvent(new Event('input', { bubbles: true }));
        element.dispatchEvent(new Event('change', { bubbles: true }));

        await this.sleep(100);

        // Check if payload was reflected
        await this.checkReflection({
          location: 'form-input',
          element,
          paramName: element.name || element.id || 'unnamed',
          originalValue,
          payload: payloadConfig.payload,
          payloadDescription: payloadConfig.description,
          context: payloadConfig.contexts[0],
        });

        // Restore original value
        element.value = originalValue;

        await this.sleep(50);
      }
    }
  }

  /**
   * Test hash fragments for DOM-based XSS
   */
  private async testHashFragments(options: ScanOptions): Promise<void> {
    console.log('🔍 Testing hash fragments...');

    const originalHash = window.location.hash;
    const payloads = PayloadLibrary.getPayloads(options.payloadComplexity || 'intermediate');

    for (const payloadConfig of payloads.slice(0, 15)) {
      // Update hash
      window.location.hash = payloadConfig.payload;

      await this.sleep(100);

      // Check if reflected in DOM
      await this.checkReflection({
        location: 'hash-fragment',
        paramName: 'hash',
        originalValue: originalHash,
        payload: payloadConfig.payload,
        payloadDescription: payloadConfig.description,
        context: payloadConfig.contexts[0],
      });

      await this.sleep(50);
    }

    // Restore original hash
    window.location.hash = originalHash;
  }

  /**
   * Test localStorage and sessionStorage for stored XSS
   */
  private async testStorageAPIs(options: ScanOptions): Promise<void> {
    console.log('🔍 Testing storage APIs...');

    const payloads = PayloadLibrary.getPayloads(options.payloadComplexity || 'basic');
    const testKey = '__xss_test_key__';

    for (const payloadConfig of payloads.slice(0, 10)) {
      // Test localStorage
      const originalLocal = localStorage.getItem(testKey);
      localStorage.setItem(testKey, payloadConfig.payload);

      await this.sleep(100);

      await this.checkReflection({
        location: 'localStorage',
        paramName: testKey,
        originalValue: originalLocal || '',
        payload: payloadConfig.payload,
        payloadDescription: payloadConfig.description,
        context: payloadConfig.contexts[0],
      });

      if (originalLocal) {
        localStorage.setItem(testKey, originalLocal);
      } else {
        localStorage.removeItem(testKey);
      }

      // Test sessionStorage
      const originalSession = sessionStorage.getItem(testKey);
      sessionStorage.setItem(testKey, payloadConfig.payload);

      await this.sleep(100);

      await this.checkReflection({
        location: 'sessionStorage',
        paramName: testKey,
        originalValue: originalSession || '',
        payload: payloadConfig.payload,
        payloadDescription: payloadConfig.description,
        context: payloadConfig.contexts[0],
      });

      if (originalSession) {
        sessionStorage.setItem(testKey, originalSession);
      } else {
        sessionStorage.removeItem(testKey);
      }

      await this.sleep(50);
    }
  }

  /**
   * Test postMessage for XSS
   */
  private async testPostMessage(options: ScanOptions): Promise<void> {
    console.log('🔍 Testing postMessage...');

    const payloads = PayloadLibrary.getPayloads(options.payloadComplexity || 'basic');

    // Listen for postMessage
    const messageHandler = (event: MessageEvent) => {
      const data = event.data;
      if (typeof data === 'string' && data.includes(this.testMarker)) {
        console.warn('🚨 XSS marker received via postMessage');
      }
    };

    window.addEventListener('message', messageHandler);

    for (const payloadConfig of payloads.slice(0, 10)) {
      window.postMessage(payloadConfig.payload, '*');

      await this.sleep(100);

      await this.checkReflection({
        location: 'postMessage',
        paramName: 'message',
        originalValue: '',
        payload: payloadConfig.payload,
        payloadDescription: payloadConfig.description,
        context: payloadConfig.contexts[0],
      });

      await this.sleep(50);
    }

    window.removeEventListener('message', messageHandler);
  }

  /**
   * Test DOM mutations for mXSS
   */
  private async testDOMMutations(options: ScanOptions): Promise<void> {
    console.log('🔍 Testing DOM mutations (mXSS)...');

    const payloads = PayloadLibrary.MUTATION_XSS;
    const testContainer = document.createElement('div');
    testContainer.style.display = 'none';
    document.body.appendChild(testContainer);

    for (const payloadConfig of payloads) {
      // Set innerHTML with payload
      testContainer.innerHTML = payloadConfig.payload;

      await this.sleep(100);

      // Check if DOM mutation changed the payload
      const mutatedHTML = testContainer.innerHTML;
      if (mutatedHTML !== payloadConfig.payload) {
        // Check if mutation created executable XSS
        const hasScript = mutatedHTML.includes('<script') ||
                         mutatedHTML.match(/on\w+\s*=/i);

        if (hasScript) {
          this.addVulnerability({
            type: VulnerabilityType.MUTATION_XSS,
            severity: SeverityLevel.HIGH,
            element: testContainer,
            sink: 'innerHTML',
            source: 'mutation',
            context: 'html',
            payload: payloadConfig.payload,
            description: `Mutation XSS detected: ${payloadConfig.description}`,
            remediation: 'Use a proper HTML sanitizer that prevents mXSS',
            proofOfConcept: `// Original: ${payloadConfig.payload}\n// Mutated: ${mutatedHTML}`,
            location: { selector: 'test-container' },
          });
        }
      }

      testContainer.innerHTML = '';
      await this.sleep(50);
    }

    document.body.removeChild(testContainer);
  }

  /**
   * Test if a payload is reflected in the page
   */
  private async testReflection(params: {
    location: string;
    paramName: string;
    originalValue: string;
    payload: string;
    payloadDescription: string;
    context: string;
  }): Promise<void> {
    await this.checkReflection(params);
  }

  /**
   * Check if payload was reflected and potentially executable
   */
  private async checkReflection(params: {
    location: string;
    element?: Element;
    paramName: string;
    originalValue: string;
    payload: string;
    payloadDescription: string;
    context: string;
  }): Promise<void> {
    const { location, element, paramName, originalValue, payload, payloadDescription, context } = params;

    // Check if payload is in DOM
    const bodyHTML = document.body.innerHTML;
    const headHTML = document.head.innerHTML;

    const isInBody = bodyHTML.includes(payload);
    const isInHead = headHTML.includes(payload);

    if (isInBody || isInHead) {
      // Check if payload was executed
      const wasExecuted = this.executedPayloads.has(payload) ||
                         this.executedPayloads.has('1') ||
                         this.executedPayloads.has('XSS');

      // Determine severity based on execution and context
      let severity = SeverityLevel.MEDIUM;
      if (wasExecuted) {
        severity = SeverityLevel.CRITICAL;
      } else if (context === 'javascript' || context === 'html') {
        severity = SeverityLevel.HIGH;
      }

      // Check context
      let actualContext = context;
      const scriptMatch = (isInBody ? bodyHTML : headHTML).match(
        new RegExp(`<script[^>]*>[^<]*${this.escapeRegex(payload)}`, 'i')
      );
      const eventMatch = (isInBody ? bodyHTML : headHTML).match(
        new RegExp(`on\\w+\\s*=\\s*["\']?[^"\']*${this.escapeRegex(payload)}`, 'i')
      );

      if (scriptMatch) {
        actualContext = 'javascript-script-tag';
        severity = SeverityLevel.CRITICAL;
      } else if (eventMatch) {
        actualContext = 'javascript-event-handler';
        severity = SeverityLevel.CRITICAL;
      }

      this.addVulnerability({
        type: VulnerabilityType.REFLECTED_XSS,
        severity,
        element: element || null,
        sink: location,
        source: paramName,
        context: actualContext,
        payload,
        description: `Reflected XSS in ${location} (${paramName}): ${payloadDescription}${wasExecuted ? ' - EXECUTED!' : ''}`,
        remediation: this.getRemediationAdvice(location, actualContext),
        proofOfConcept: this.generateProofOfConcept(location, paramName, payload, wasExecuted),
        location: element ? this.getElementLocation(element) : { selector: location },
      });

      if (wasExecuted) {
        console.error(`🚨 CRITICAL: XSS payload executed in ${location}!`);
      } else {
        console.warn(`⚠️  XSS payload reflected in ${location}`);
      }
    }
  }

  /**
   * Get remediation advice based on location and context
   */
  private getRemediationAdvice(location: string, context: string): string {
    const advice: Record<string, string> = {
      'url-parameter': 'Sanitize all URL parameters before reflecting in HTML. Use textContent instead of innerHTML, or use a library like DOMPurify.',
      'form-input': 'Validate and sanitize all user input. Never reflect input directly in HTML without encoding.',
      'hash-fragment': 'Avoid using location.hash directly in innerHTML or eval. Validate and encode before use.',
      'localStorage': 'Treat localStorage as untrusted. Sanitize before rendering in DOM.',
      'sessionStorage': 'Treat sessionStorage as untrusted. Sanitize before rendering in DOM.',
      'postMessage': 'Validate postMessage origin and sanitize message content before use.',
    };

    return advice[location] || 'Sanitize all user-controlled data before using in DOM manipulation.';
  }

  /**
   * Generate proof of concept for vulnerability
   */
  private generateProofOfConcept(location: string, paramName: string, payload: string, wasExecuted: boolean): string {
    let poc = `// Vulnerability Location: ${location}\n`;
    poc += `// Parameter: ${paramName}\n`;
    poc += `// Payload: ${payload}\n`;

    if (wasExecuted) {
      poc += `// STATUS: PAYLOAD EXECUTED ✓\n`;
    } else {
      poc += `// STATUS: Payload reflected but not executed\n`;
    }

    if (location === 'url-parameter') {
      const url = new URL(window.location.href);
      url.searchParams.set(paramName, payload);
      poc += `\n// PoC URL:\n${url.toString()}`;
    }

    return poc;
  }

  /**
   * Get element location
   */
  private getElementLocation(element: Element): any {
    return {
      selector: element.id ? `#${element.id}` : element.tagName.toLowerCase(),
    };
  }

  /**
   * Add vulnerability
   */
  private addVulnerability(vuln: Omit<Vulnerability, 'id'>): void {
    const id = `${vuln.type}-${vuln.sink}-${Date.now()}-${Math.random()}`;
    this.vulnerabilities.push({ ...vuln, id });
  }

  /**
   * Escape string for regex
   */
  private escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Sleep helper
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
