/**
 * XSS Guardian - Main class that orchestrates all detection modules
 */

import { ScanOptions, ScanResult, Vulnerability, SeverityLevel } from './types';
import { DOMAnalyzer } from './detectors/dom-analyzer';
import { MutationTester } from './detectors/mutation-tester';
import {
  FrameworkDetectionService,
  AureliaAnalyzer,
  ReactAnalyzer,
  VueAnalyzer,
  AngularAnalyzer,
  AlpineAnalyzer,
} from './detectors/framework-detector';
import { VulnerabilityReporter } from './reporter';

export class XSSGuardian {
  private domAnalyzer: DOMAnalyzer;
  private mutationTester: MutationTester;
  private frameworkDetector: FrameworkDetectionService;
  private reporter: VulnerabilityReporter;

  private frameworkAnalyzers = [
    new AureliaAnalyzer(),
    new ReactAnalyzer(),
    new VueAnalyzer(),
    new AngularAnalyzer(),
    new AlpineAnalyzer(),
  ];

  constructor() {
    this.domAnalyzer = new DOMAnalyzer();
    this.mutationTester = new MutationTester();
    this.frameworkDetector = new FrameworkDetectionService();
    this.reporter = new VulnerabilityReporter();

    this.printWelcome();
  }

  /**
   * Run comprehensive XSS scan
   */
  async scan(options: ScanOptions = {}): Promise<ScanResult> {
    const startTime = performance.now();

    console.log('🔍 Starting XSS Guardian scan...');
    console.log('');

    // Detect frameworks
    const detectedFrameworks = this.frameworkDetector.detectFrameworks();
    console.log('');

    // Collect all vulnerabilities
    const allVulnerabilities: Vulnerability[] = [];

    // Phase 1: DOM Analysis
    console.log('📊 Phase 1: Analyzing DOM structure...');
    const domVulns = this.domAnalyzer.scan(options);
    allVulnerabilities.push(...domVulns);
    console.log(`   Found ${domVulns.length} potential DOM vulnerabilities`);
    console.log('');

    // Phase 2: Framework-specific analysis
    console.log('🎯 Phase 2: Framework-specific analysis...');
    for (const analyzer of this.frameworkAnalyzers) {
      if (analyzer.detect()) {
        const frameworkVulns = analyzer.scan(options);
        allVulnerabilities.push(...frameworkVulns);
        console.log(`   ${analyzer.name}: Found ${frameworkVulns.length} vulnerabilities`);
      }
    }
    console.log('');

    // Phase 3: Mutation testing (if enabled)
    if (options.mutationTest) {
      console.log('🧪 Phase 3: Mutation-based testing (this may take a while)...');
      console.log('   ⚠️  WARNING: This will modify the page temporarily');

      const userConfirm = confirm(
        'Mutation testing will modify URL parameters, form inputs, and storage to test for reflected XSS. Continue?'
      );

      if (userConfirm) {
        const mutationVulns = await this.mutationTester.test(options);
        allVulnerabilities.push(...mutationVulns);
        console.log(`   Found ${mutationVulns.length} reflected/mutation XSS vulnerabilities`);
      } else {
        console.log('   Mutation testing skipped by user');
      }
      console.log('');
    }

    // Calculate summary
    const summary = this.calculateSummary(allVulnerabilities);

    // Create scan result
    const scanResult: ScanResult = {
      summary,
      vulnerabilities: allVulnerabilities,
      scanDuration: performance.now() - startTime,
      timestamp: new Date(),
      detectedFrameworks,
      scanOptions: options,
    };

    // Generate report
    this.reporter.report(scanResult);

    return scanResult;
  }

  /**
   * Quick scan (no mutation testing)
   */
  async quickScan(): Promise<ScanResult> {
    return this.scan({
      depth: 10,
      includeShadowDOM: true,
      includeIframes: false,
      mutationTest: false,
      payloadComplexity: 'basic',
      verbose: false,
    });
  }

  /**
   * Deep scan (with mutation testing)
   */
  async deepScan(): Promise<ScanResult> {
    return this.scan({
      depth: 100,
      includeShadowDOM: true,
      includeIframes: true,
      mutationTest: true,
      payloadComplexity: 'all',
      verbose: true,
    });
  }

  /**
   * Framework-focused scan
   */
  async frameworkScan(frameworks?: string[]): Promise<ScanResult> {
    return this.scan({
      frameworks,
      includeShadowDOM: true,
      payloadComplexity: 'advanced',
    });
  }

  /**
   * Calculate vulnerability summary
   */
  private calculateSummary(vulnerabilities: Vulnerability[]) {
    return {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.severity === SeverityLevel.CRITICAL).length,
      high: vulnerabilities.filter(v => v.severity === SeverityLevel.HIGH).length,
      medium: vulnerabilities.filter(v => v.severity === SeverityLevel.MEDIUM).length,
      low: vulnerabilities.filter(v => v.severity === SeverityLevel.LOW).length,
      info: vulnerabilities.filter(v => v.severity === SeverityLevel.INFO).length,
    };
  }

  /**
   * Export report in various formats
   */
  exportReport(result: ScanResult, format: 'json' | 'html' = 'html'): void {
    this.reporter.downloadReport(result, format);
  }

  /**
   * Get last scan result
   */
  private lastResult: ScanResult | null = null;

  getLastResult(): ScanResult | null {
    return this.lastResult;
  }

  /**
   * Print welcome message
   */
  private printWelcome(): void {
    console.log(
      '%c' + '╔══════════════════════════════════════════════════════════════╗',
      'color: #9d4edd; font-weight: bold;'
    );
    console.log(
      '%c' + '║           🛡️  XSS GUARDIAN LOADED 🛡️                       ║',
      'color: #9d4edd; font-weight: bold; font-size: 14px;'
    );
    console.log(
      '%c' + '╚══════════════════════════════════════════════════════════════╝',
      'color: #9d4edd; font-weight: bold;'
    );
    console.log('');
    console.log('%cAvailable commands:', 'color: #00bfff; font-weight: bold;');
    console.log('%c  XSSGuardian.scan(options)       %c- Full scan with custom options', 'color: #00ff00;', 'color: #ffffff;');
    console.log('%c  XSSGuardian.quickScan()         %c- Quick scan (no mutation testing)', 'color: #00ff00;', 'color: #ffffff;');
    console.log('%c  XSSGuardian.deepScan()          %c- Deep scan (with mutation testing)', 'color: #00ff00;', 'color: #ffffff;');
    console.log('%c  XSSGuardian.frameworkScan()     %c- Framework-focused scan', 'color: #00ff00;', 'color: #ffffff;');
    console.log('%c  XSSGuardian.exportReport(result, format) %c- Export report (json/html)', 'color: #00ff00;', 'color: #ffffff;');
    console.log('');
    console.log('%cExample:', 'color: #ffa500; font-weight: bold;');
    console.log('%c  const result = await XSSGuardian.quickScan();', 'color: #ffffff; font-family: monospace;');
    console.log('');
  }

  /**
   * Static factory method for easy initialization
   */
  static create(): XSSGuardian {
    return new XSSGuardian();
  }

  /**
   * Auto-scan on load
   */
  static async autoScan(options: ScanOptions = {}): Promise<ScanResult> {
    const guardian = new XSSGuardian();
    return guardian.scan(options);
  }
}

// Global instance
(window as any).XSSGuardian = XSSGuardian.create();

// Export for module usage
export default XSSGuardian;
