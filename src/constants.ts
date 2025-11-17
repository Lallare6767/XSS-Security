/**
 * Comprehensive constants for XSS detection
 */

import { DOMSink, DOMSource } from './types';

// Dangerous DOM sinks that can execute JavaScript
export const DOM_SINKS: DOMSink[] = [
  // HTML sinks
  { property: 'innerHTML', object: 'Element', dangerous: true, requiresUserInteraction: false, context: 'html' },
  { property: 'outerHTML', object: 'Element', dangerous: true, requiresUserInteraction: false, context: 'html' },
  { property: 'insertAdjacentHTML', object: 'Element', dangerous: true, requiresUserInteraction: false, context: 'html' },
  { property: 'write', object: 'document', dangerous: true, requiresUserInteraction: false, context: 'html' },
  { property: 'writeln', object: 'document', dangerous: true, requiresUserInteraction: false, context: 'html' },

  // JavaScript execution sinks
  { property: 'eval', object: 'window', dangerous: true, requiresUserInteraction: false, context: 'javascript' },
  { property: 'setTimeout', object: 'window', dangerous: true, requiresUserInteraction: false, context: 'javascript' },
  { property: 'setInterval', object: 'window', dangerous: true, requiresUserInteraction: false, context: 'javascript' },
  { property: 'Function', object: 'window', dangerous: true, requiresUserInteraction: false, context: 'javascript' },
  { property: 'setImmediate', object: 'window', dangerous: true, requiresUserInteraction: false, context: 'javascript' },
  { property: 'execScript', object: 'window', dangerous: true, requiresUserInteraction: false, context: 'javascript' },

  // Script manipulation
  { property: 'src', object: 'HTMLScriptElement', dangerous: true, requiresUserInteraction: false, context: 'url' },
  { property: 'text', object: 'HTMLScriptElement', dangerous: true, requiresUserInteraction: false, context: 'javascript' },
  { property: 'textContent', object: 'HTMLScriptElement', dangerous: true, requiresUserInteraction: false, context: 'javascript' },
  { property: 'innerText', object: 'HTMLScriptElement', dangerous: true, requiresUserInteraction: false, context: 'javascript' },

  // URL-based sinks
  { property: 'href', object: 'HTMLAnchorElement', dangerous: true, requiresUserInteraction: true, context: 'url' },
  { property: 'src', object: 'HTMLIFrameElement', dangerous: true, requiresUserInteraction: false, context: 'url' },
  { property: 'src', object: 'HTMLEmbedElement', dangerous: true, requiresUserInteraction: false, context: 'url' },
  { property: 'src', object: 'HTMLImageElement', dangerous: true, requiresUserInteraction: false, context: 'url' },
  { property: 'action', object: 'HTMLFormElement', dangerous: true, requiresUserInteraction: true, context: 'url' },
  { property: 'formAction', object: 'HTMLButtonElement', dangerous: true, requiresUserInteraction: true, context: 'url' },
  { property: 'location', object: 'window', dangerous: true, requiresUserInteraction: false, context: 'url' },
  { property: 'location.href', object: 'window', dangerous: true, requiresUserInteraction: false, context: 'url' },

  // Event handlers
  { property: 'onclick', object: 'Element', dangerous: true, requiresUserInteraction: true, context: 'javascript' },
  { property: 'onerror', object: 'Element', dangerous: true, requiresUserInteraction: false, context: 'javascript' },
  { property: 'onload', object: 'Element', dangerous: true, requiresUserInteraction: false, context: 'javascript' },
  { property: 'onmouseover', object: 'Element', dangerous: true, requiresUserInteraction: true, context: 'javascript' },

  // jQuery specific
  { property: 'html', object: 'jQuery', dangerous: true, requiresUserInteraction: false, context: 'html' },
  { property: 'append', object: 'jQuery', dangerous: true, requiresUserInteraction: false, context: 'html' },
  { property: 'prepend', object: 'jQuery', dangerous: true, requiresUserInteraction: false, context: 'html' },
  { property: 'after', object: 'jQuery', dangerous: true, requiresUserInteraction: false, context: 'html' },
  { property: 'before', object: 'jQuery', dangerous: true, requiresUserInteraction: false, context: 'html' },
  { property: 'replaceWith', object: 'jQuery', dangerous: true, requiresUserInteraction: false, context: 'html' },

  // Aurelia specific
  { property: 'innerhtml.bind', object: 'Aurelia', dangerous: true, requiresUserInteraction: false, context: 'html', frameworks: ['aurelia'] },
  { property: 'innerhtml.one-time', object: 'Aurelia', dangerous: true, requiresUserInteraction: false, context: 'html', frameworks: ['aurelia'] },

  // React specific (via dangerouslySetInnerHTML)
  { property: 'dangerouslySetInnerHTML', object: 'React', dangerous: true, requiresUserInteraction: false, context: 'html', frameworks: ['react'] },

  // Vue specific
  { property: 'v-html', object: 'Vue', dangerous: true, requiresUserInteraction: false, context: 'html', frameworks: ['vue'] },

  // Angular specific
  { property: 'bypassSecurityTrustHtml', object: 'Angular', dangerous: true, requiresUserInteraction: false, context: 'html', frameworks: ['angular'] },
  { property: 'bypassSecurityTrustScript', object: 'Angular', dangerous: true, requiresUserInteraction: false, context: 'javascript', frameworks: ['angular'] },
  { property: 'bypassSecurityTrustUrl', object: 'Angular', dangerous: true, requiresUserInteraction: false, context: 'url', frameworks: ['angular'] },
];

// DOM sources that can be controlled by attackers
export const DOM_SOURCES: DOMSource[] = [
  // URL-based sources
  { property: 'location.hash', object: 'window', controllable: true, requiresUserInput: false },
  { property: 'location.search', object: 'window', controllable: true, requiresUserInput: false },
  { property: 'location.href', object: 'window', controllable: true, requiresUserInput: false },
  { property: 'location.pathname', object: 'window', controllable: true, requiresUserInput: false },
  { property: 'document.URL', object: 'document', controllable: true, requiresUserInput: false },
  { property: 'document.documentURI', object: 'document', controllable: true, requiresUserInput: false },
  { property: 'document.baseURI', object: 'document', controllable: true, requiresUserInput: false },

  // Referrer
  { property: 'document.referrer', object: 'document', controllable: true, requiresUserInput: false },

  // User input
  { property: 'value', object: 'HTMLInputElement', controllable: true, requiresUserInput: true },
  { property: 'value', object: 'HTMLTextAreaElement', controllable: true, requiresUserInput: true },
  { property: 'value', object: 'HTMLSelectElement', controllable: true, requiresUserInput: true },

  // PostMessage
  { property: 'data', object: 'MessageEvent', controllable: true, requiresUserInput: false },

  // Storage
  { property: 'localStorage', object: 'window', controllable: true, requiresUserInput: false },
  { property: 'sessionStorage', object: 'window', controllable: true, requiresUserInput: false },

  // Cookies
  { property: 'cookie', object: 'document', controllable: true, requiresUserInput: false },

  // WebSocket
  { property: 'data', object: 'WebSocket', controllable: true, requiresUserInput: false },
];

// Event handlers that can execute JavaScript
export const EVENT_HANDLERS = [
  'onabort', 'onblur', 'onchange', 'onclick', 'oncontextmenu', 'ondblclick',
  'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart',
  'ondrop', 'onerror', 'onfocus', 'oninput', 'oninvalid', 'onkeydown', 'onkeypress',
  'onkeyup', 'onload', 'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove',
  'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel', 'onscroll', 'onselect',
  'onsubmit', 'onwheel', 'oncopy', 'oncut', 'onpaste', 'onanimationend',
  'onanimationiteration', 'onanimationstart', 'ontransitionend', 'onpointerdown',
  'onpointerup', 'onpointermove', 'onpointerover', 'onpointerout', 'onpointerenter',
  'onpointerleave', 'onpointercancel', 'ontouchstart', 'ontouchmove', 'ontouchend',
  'ontouchcancel', 'onseeked', 'onseeking', 'onshow', 'onstalled', 'onsuspend',
  'ontimeupdate', 'onvolumechange', 'onwaiting', 'onafterprint', 'onbeforeprint',
  'onbeforeunload', 'onhashchange', 'onmessage', 'onoffline', 'ononline',
  'onpagehide', 'onpageshow', 'onpopstate', 'onstorage', 'onunload', 'ontoggle',
];

// Dangerous HTML attributes
export const DANGEROUS_ATTRIBUTES = [
  'href', 'src', 'action', 'formaction', 'data', 'srcdoc', 'cite', 'codebase',
  'background', 'poster', 'icon', 'manifest', 'archive', 'classid', 'usemap',
  ...EVENT_HANDLERS,
];

// HTML tags that can execute JavaScript
export const DANGEROUS_TAGS = [
  'script', 'iframe', 'embed', 'object', 'applet', 'meta', 'link', 'style',
  'base', 'form', 'input', 'button', 'select', 'textarea', 'keygen', 'video',
  'audio', 'track', 'source', 'img', 'image', 'svg', 'math', 'details',
];

// Framework detection patterns
export const FRAMEWORK_PATTERNS = {
  react: {
    properties: ['__REACT_DEVTOOLS_GLOBAL_HOOK__', '_reactRootContainer', '__reactInternalInstance'],
    attributes: ['data-reactroot', 'data-reactid'],
    globalCheck: () => !!(window as any).React || document.querySelector('[data-reactroot], [data-reactid]'),
  },
  vue: {
    properties: ['__VUE__', '__vue__'],
    attributes: ['data-v-', 'v-cloak', 'v-if', 'v-for', 'v-html'],
    globalCheck: () => !!(window as any).Vue || !!document.querySelector('[data-v-]'),
  },
  angular: {
    properties: ['ng', 'getAllAngularRootElements'],
    attributes: ['ng-app', 'ng-version', 'ng-controller', '_nghost-', '_ngcontent-'],
    globalCheck: () => !!(window as any).ng || !!document.querySelector('[ng-version], [ng-app]'),
  },
  aurelia: {
    properties: ['au'],
    attributes: ['au-target-id', 'aurelia-app', 'innerhtml.bind', 'innerhtml.one-time'],
    globalCheck: () => !!(window as any).au || !!document.querySelector('[au-target-id], [aurelia-app]'),
  },
  jquery: {
    properties: ['jQuery', '$'],
    attributes: [],
    globalCheck: () => typeof (window as any).jQuery !== 'undefined',
  },
  svelte: {
    properties: ['__svelte'],
    attributes: ['svelte-', 'class:'],
    globalCheck: () => !!document.querySelector('[class*="svelte-"]'),
  },
  alpine: {
    properties: ['Alpine'],
    attributes: ['x-data', 'x-html', 'x-text'],
    globalCheck: () => !!(window as any).Alpine || !!document.querySelector('[x-data]'),
  },
};

// Content Security Policy bypasses
export const CSP_BYPASS_TECHNIQUES = [
  'script-src \'unsafe-inline\'',
  'script-src \'unsafe-eval\'',
  'script-src data:',
  'script-src *',
  'base-uri missing',
  'jsonp endpoints',
  'angular expressions',
  'dangling markup injection',
];
