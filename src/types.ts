/**
 * Core type definitions for XSS Guardian
 */

export enum VulnerabilityType {
  DOM_XSS = 'DOM_XSS',
  REFLECTED_XSS = 'REFLECTED_XSS',
  STORED_XSS = 'STORED_XSS',
  MUTATION_XSS = 'MUTATION_XSS',
  PROTOTYPE_POLLUTION = 'PROTOTYPE_POLLUTION',
  TEMPLATE_INJECTION = 'TEMPLATE_INJECTION',
}

export enum SeverityLevel {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO',
}

export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: SeverityLevel;
  element: Element | null;
  sink: string;
  source: string;
  context: string;
  payload: string;
  description: string;
  remediation: string;
  stackTrace?: string;
  framework?: string;
  proofOfConcept?: string;
  location: {
    file?: string;
    line?: number;
    column?: number;
    xpath?: string;
    selector?: string;
  };
}

export interface ScanOptions {
  depth?: number;
  includeShadowDOM?: boolean;
  includeIframes?: boolean;
  mutationTest?: boolean;
  frameworks?: string[];
  customSinks?: string[];
  customSources?: string[];
  payloadComplexity?: 'basic' | 'intermediate' | 'advanced' | 'all';
  verbose?: boolean;
  autoRemediate?: boolean;
}

export interface ScanResult {
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  vulnerabilities: Vulnerability[];
  scanDuration: number;
  timestamp: Date;
  detectedFrameworks: string[];
  scanOptions: ScanOptions;
}

export interface DOMSink {
  property: string;
  object: string;
  dangerous: boolean;
  requiresUserInteraction: boolean;
  context: 'html' | 'javascript' | 'url' | 'css' | 'attribute';
  frameworks?: string[];
}

export interface DOMSource {
  property: string;
  object: string;
  controllable: boolean;
  requiresUserInput: boolean;
}

export interface PayloadConfig {
  payload: string;
  contexts: string[];
  encoding?: string;
  description: string;
  bypassTechnique?: string;
}

export interface FrameworkDetector {
  name: string;
  detect: () => boolean;
  version?: () => string | null;
  sinks: DOMSink[];
  sources: DOMSource[];
  scan: (options: ScanOptions) => Vulnerability[];
}
