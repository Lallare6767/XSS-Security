/**
 * XSS Guardian - Main entry point
 */

import XSSGuardian from './xss-guardian';

export { XSSGuardian };
export * from './types';
export * from './constants';
export * from './payloads';
export * from './reporter';
export * from './detectors/dom-analyzer';
export * from './detectors/mutation-tester';
export * from './detectors/framework-detector';

// Auto-initialize when loaded in browser
if (typeof window !== 'undefined') {
  (window as any).XSSGuardian = XSSGuardian.create();

  console.log(
    '%c🛡️ XSS Guardian loaded and ready!',
    'color: #00ff00; font-size: 16px; font-weight: bold;'
  );
  console.log(
    '%cType "XSSGuardian.quickScan()" to start scanning',
    'color: #00bfff; font-size: 14px;'
  );
}

export default XSSGuardian;
