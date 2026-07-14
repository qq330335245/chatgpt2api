#!/usr/bin/env node

const fs = require("fs");
const vm = require("vm");
const crypto = require("crypto");
const { TextEncoder } = require("util");

const SDK_URL = "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js";
const FRAME_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6";

function parseArgs(argv) {
  const result = {
    flow: "authorize_continue",
    deviceId: crypto.randomUUID(),
    sdkPath: "analysis_artifacts/sentinel_assets/live_sentinel_20260219f9f6_sdk.js",
    full: false,
    withSo: false,
    bundleOutput: false,
    debug: false,
    dumpReq: "",
    out: "",
    pageUrl: "",
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    language: "en-US",
    languages: "en-US,en",
    screenWidth: 1920,
    screenHeight: 1080,
    screenAvailHeight: 0,
    colorDepth: 24,
    pixelDepth: 24,
    jsHeapSizeLimit: 4294705152,
    hardwareConcurrency: 8,
    deviceMemory: 8,
    maxTouchPoints: 0,
    historyLength: 1,
    localStorageKeys: "",
    elementRectY: 0,
    cfConnectingIp: "",
    cfIpCity: "",
    cfIpLatitude: "",
    cfIpLongitude: "",
    userRegion: "",
    cookieHeader: "",
    fetchCookieHeader: null,
  };
  for (let i = 2; i < argv.length; i++) {
    const item = argv[i];
    if (item === "--flow") result.flow = argv[++i] || result.flow;
    else if (item === "--device-id") result.deviceId = argv[++i] || result.deviceId;
    else if (item === "--sdk") result.sdkPath = argv[++i] || result.sdkPath;
    else if (item === "--full") result.full = true;
    else if (item === "--with-so") result.withSo = true;
    else if (item === "--bundle-output") result.bundleOutput = true;
    else if (item === "--debug") result.debug = true;
    else if (item === "--dump-req") result.dumpReq = argv[++i] || "";
    else if (item === "--out") result.out = argv[++i] || "";
    else if (item === "--page-url") result.pageUrl = argv[++i] || "";
    else if (item === "--user-agent") result.userAgent = argv[++i] || result.userAgent;
    else if (item === "--language") result.language = argv[++i] || result.language;
    else if (item === "--languages") result.languages = argv[++i] || result.languages;
    else if (item === "--screen-width") result.screenWidth = Number(argv[++i] || result.screenWidth);
    else if (item === "--screen-height") result.screenHeight = Number(argv[++i] || result.screenHeight);
    else if (item === "--screen-avail-height") result.screenAvailHeight = Number(argv[++i] || result.screenAvailHeight);
    else if (item === "--color-depth") result.colorDepth = Number(argv[++i] || result.colorDepth);
    else if (item === "--pixel-depth") result.pixelDepth = Number(argv[++i] || result.pixelDepth);
    else if (item === "--js-heap-size-limit") result.jsHeapSizeLimit = Number(argv[++i] || result.jsHeapSizeLimit);
    else if (item === "--hardware-concurrency") result.hardwareConcurrency = Number(argv[++i] || result.hardwareConcurrency);
    else if (item === "--device-memory") result.deviceMemory = Number(argv[++i] || result.deviceMemory);
    else if (item === "--max-touch-points") result.maxTouchPoints = Number(argv[++i] || result.maxTouchPoints);
    else if (item === "--history-length") result.historyLength = Number(argv[++i] || result.historyLength);
    else if (item === "--local-storage-keys") result.localStorageKeys = argv[++i] || result.localStorageKeys;
    else if (item === "--element-rect-y") result.elementRectY = Number(argv[++i] || result.elementRectY);
    else if (item === "--cf-connecting-ip") result.cfConnectingIp = argv[++i] || result.cfConnectingIp;
    else if (item === "--cf-ip-city") result.cfIpCity = argv[++i] || result.cfIpCity;
    else if (item === "--cf-ip-latitude") result.cfIpLatitude = argv[++i] || result.cfIpLatitude;
    else if (item === "--cf-ip-longitude") result.cfIpLongitude = argv[++i] || result.cfIpLongitude;
    else if (item === "--user-region") result.userRegion = argv[++i] || result.userRegion;
    else if (item === "--cookie-header") result.cookieHeader = argv[++i] || result.cookieHeader;
    else if (item === "--fetch-cookie-header") result.fetchCookieHeader = argv[++i] || "";
  }
  return result;
}

function btoaNode(value) {
  return Buffer.from(String(value), "binary").toString("base64");
}

function atobNode(value) {
  return Buffer.from(String(value), "base64").toString("binary");
}

class FakeEventTarget {
  constructor() {
    this.listeners = new Map();
  }

  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(handler);
  }

  dispatchEvent(type, event) {
    for (const handler of this.listeners.get(type) || []) {
      handler(event);
    }
  }
}

class FakeStorage {
  constructor() {
    Object.defineProperty(this, "items", {
      value: new Map(),
      enumerable: false,
      configurable: false,
      writable: false,
    });
  }

  get length() {
    return this.items.size;
  }

  clear() {
    this.items.clear();
  }

  getItem(key) {
    const name = String(key);
    return this.items.has(name) ? this.items.get(name) : null;
  }

  key(index) {
    return Array.from(this.items.keys())[Number(index)] ?? null;
  }

  removeItem(key) {
    const name = String(key);
    this.items.delete(name);
    delete this[name];
  }

  setItem(key, value) {
    const name = String(key);
    const item = String(value);
    this.items.set(name, item);
    Object.defineProperty(this, name, {
      value: item,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
}

function createEventTargetMethods(target) {
  return {
    addEventListener: target.addEventListener.bind(target),
    removeEventListener(type, handler) {
      const listeners = target.listeners.get(type) || [];
      target.listeners.set(
        type,
        listeners.filter((item) => item !== handler),
      );
    },
    dispatchEvent(event) {
      target.dispatchEvent(event?.type || event, event);
      return true;
    },
  };
}

function setToStringTag(target, tag) {
  try {
    Object.defineProperty(target, Symbol.toStringTag, {
      value: tag,
      configurable: true,
    });
  } catch {}
  return target;
}

function createDocument({ currentScriptUrl, cookie, href, options }) {
  const target = new FakeEventTarget();
  const scripts = [{ src: currentScriptUrl, length: 1 }];
  const document = {
    currentScript: scripts[0],
    scripts,
    cookie,
    referrer: "https://auth.openai.com/",
    URL: href,
    visibilityState: "visible",
    hidden: false,
    readyState: "complete",
    documentElement: {
      getAttribute(name) {
        if (name === "data-build") return null;
        return null;
      },
      style: {},
      clientWidth: 1920,
      clientHeight: 1080,
    },
    body: {
      children: [],
      childNodes: [],
      innerHTML: "",
      textContent: "",
      style: {},
      appendChild(node) {
        this.children.push(node);
        this.childNodes.push(node);
        if (typeof node.onload === "function") setTimeout(node.onload, 0);
        return node;
      },
      insertBefore(node) {
        this.children.push(node);
        this.childNodes.push(node);
        return node;
      },
      removeChild(node) {
        this.children = this.children.filter((item) => item !== node);
        this.childNodes = this.childNodes.filter((item) => item !== node);
        return node;
      },
      getBoundingClientRect() {
        return { x: 0, y: 0, width: 1920, height: 1080, top: 0, left: 0, right: 1920, bottom: 1080 };
      },
    },
    createElement(tag) {
      const node = {
        tagName: String(tag || "").toUpperCase(),
        style: {},
        src: "",
        addEventListener(type, handler) {
          if (type === "load") node.onload = handler;
        },
        removeEventListener() {},
        setAttribute(name, value) {
          node[String(name)] = String(value);
        },
        getAttribute(name) {
          return node[String(name)] ?? null;
        },
        appendChild(child) {
          node.children = node.children || [];
          node.children.push(child);
          return child;
        },
        insertBefore(child) {
          node.children = node.children || [];
          node.children.push(child);
          return child;
        },
        removeChild(child) {
          node.children = (node.children || []).filter((item) => item !== child);
          return child;
        },
        getContext() {
          return null;
        },
        getBoundingClientRect() {
          const width = Number.parseFloat(String(node.style?.width || "")) || (node.tagName === "DIV" ? 27.484375 : 0);
          const height = Number.parseFloat(String(node.style?.height || "")) || (node.tagName === "DIV" ? 23 : 0);
          const y = Number(options.elementRectY || 0);
          return { x: 0, y, width, height, top: y, left: 0, right: width, bottom: y + height };
        },
      };
      setToStringTag(node, node.tagName === "DIV" ? "HTMLDivElement" : "HTMLElement");
      return node;
    },
    getElementById() {
      return null;
    },
    getElementsByTagName(tag) {
      return String(tag || "").toLowerCase() === "script" ? scripts : [];
    },
    querySelector() {
      return null;
    },
    querySelectorAll() {
      return [];
    },
    ...createEventTargetMethods(target),
  };
  document["__reactContainer$vpvbqpp6s1a"] = {};
  document["__reactEvents$vpvbqpp6s1a"] = new Set();
  document.location = new URL(document.URL);
  document.compatMode = "CSS1Compat";
  document.characterSet = "UTF-8";
  document.contentType = "text/html";
  setToStringTag(document, "HTMLDocument");
  setToStringTag(document.documentElement, "HTMLHtmlElement");
  setToStringTag(document.body, "HTMLBodyElement");
  return document;
}

function createNativeLikeFunction(name, impl) {
  const fn = impl || function () {};
  try {
    Object.defineProperty(fn, "name", { value: name, configurable: true });
  } catch {}
  fn.toString = () => `function ${name}() { [native code] }`;
  return fn;
}

function createNavigator(options) {
  const proto = {};
  Object.defineProperties(proto, {
    pdfViewerEnabled: { value: true, enumerable: true, writable: true, configurable: true },
    webdriver: { value: false, enumerable: true, writable: true, configurable: true },
    vendorSub: { value: "", enumerable: true, writable: true, configurable: true },
    productSub: { value: "20030107", enumerable: true, writable: true, configurable: true },
    bluetooth: { value: {}, enumerable: true, writable: true, configurable: true },
    clipboard: { value: {}, enumerable: true, writable: true, configurable: true },
    credentials: { value: {}, enumerable: true, writable: true, configurable: true },
    keyboard: { value: {}, enumerable: true, writable: true, configurable: true },
    mediaDevices: { value: {}, enumerable: true, writable: true, configurable: true },
    storage: { value: {}, enumerable: true, writable: true, configurable: true },
    javaEnabled: {
      value: createNativeLikeFunction("javaEnabled", function javaEnabled() { return false; }),
      enumerable: true,
      writable: true,
      configurable: true,
    },
    getBattery: {
      value: createNativeLikeFunction("getBattery", function getBattery() {
        return Promise.resolve({ charging: true, level: 1 });
      }),
      enumerable: true,
      writable: true,
      configurable: true,
    },
  });
  const navigator = Object.assign(Object.create(proto), {
    userAgent: options.userAgent,
    language: options.language,
    languages: String(options.languages || options.language || "en-US").split(",").map((item) => item.trim()).filter(Boolean),
    hardwareConcurrency: Number(options.hardwareConcurrency || 8),
    cookieEnabled: true,
    vendor: "Google Inc.",
    productSub: "20030107",
    maxTouchPoints: Number(options.maxTouchPoints || 0),
    webdriver: false,
    platform: "Win32",
    deviceMemory: Number(options.deviceMemory || 8),
    pdfViewerEnabled: true,
    plugins: [
      { name: "PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
      { name: "Chrome PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
      { name: "Chromium PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
      { name: "Microsoft Edge PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
      { name: "WebKit built-in PDF", filename: "internal-pdf-viewer", description: "Portable Document Format" },
    ],
    mimeTypes: [{ type: "application/pdf", suffixes: "pdf", description: "Portable Document Format" }],
    permissions: {
      query: async () => ({ state: "prompt", onchange: null }),
    },
    connection: {
      downlink: 10,
      effectiveType: "4g",
      rtt: 50,
      saveData: false,
    },
  });
  return setToStringTag(navigator, "Navigator");
}

function createWindow({ href, currentScriptUrl, cookie, topWindow, options }) {
  const target = new FakeEventTarget();
  const localStorage = new FakeStorage();
  const sessionStorage = new FakeStorage();
  for (const key of String(options.localStorageKeys || "").split(",").map((item) => item.trim()).filter(Boolean)) {
    localStorage.setItem(key, "");
  }
  setToStringTag(localStorage, "Storage");
  setToStringTag(sessionStorage, "Storage");
  const clientBootstrap = {
    cfConnectingIp: String(options.cfConnectingIp || ""),
    cfIpCity: String(options.cfIpCity || ""),
    cfIpLatitude: String(options.cfIpLatitude || ""),
    cfIpLongitude: String(options.cfIpLongitude || ""),
    userRegion: String(options.userRegion || ""),
  };
  const hasClientBootstrap = Object.values(clientBootstrap).some(Boolean);
  const win = {
    location: new URL(href),
    top: topWindow || null,
    parent: topWindow || null,
    document: createDocument({ currentScriptUrl, cookie, href, options }),
    history: setToStringTag({
      length: Number(options.historyLength || 1),
      state: null,
      back() {},
      forward() {},
      go() {},
      pushState(state) {
        this.state = state;
      },
      replaceState(state) {
        this.state = state;
      },
    }, "History"),
    localStorage,
    sessionStorage,
    navigator: createNavigator(options),
    screen: setToStringTag({
      width: Number(options.screenWidth || 1920),
      height: Number(options.screenHeight || 1080),
      availWidth: Number(options.screenWidth || 1920),
      availHeight: Number(options.screenAvailHeight || 0) || Math.max(0, Number(options.screenHeight || 1080) - 40),
      availLeft: 0,
      availTop: 0,
      colorDepth: Number(options.colorDepth || 24),
      pixelDepth: Number(options.pixelDepth || 24),
    }, "Screen"),
    ...(hasClientBootstrap
      ? {
          clientBootstrap,
          loaderData: { root: { clientBootstrap } },
          __reactRouterContext: {
            state: {
              loaderData: { root: { clientBootstrap } },
            },
          },
        }
      : {}),
    innerWidth: Number(options.screenWidth || 1920),
    innerHeight: Number(options.screenHeight || 1080),
    outerWidth: Number(options.screenWidth || 1920),
    outerHeight: Number(options.screenHeight || 1080),
    devicePixelRatio: 1,
    performance: setToStringTag({
      now: () => Number(process.hrtime.bigint() / 1000000n),
      timeOrigin: Date.now() - 1000,
      memory: { jsHeapSizeLimit: Number(options.jsHeapSizeLimit || 4294705152) },
      getEntriesByType: () => [],
      mark() {},
      measure() {},
    }, "Performance"),
    crypto: {
      randomUUID: crypto.randomUUID,
      getRandomValues(arr) {
        return crypto.webcrypto.getRandomValues(arr);
      },
    },
    TextEncoder,
    btoa: btoaNode,
    atob: atobNode,
    URL,
    URLSearchParams,
    setTimeout,
    clearTimeout,
    console,
    ...createEventTargetMethods(target),
    __dispatch: target.dispatchEvent.bind(target),
    postMessage() {},
    getComputedStyle() {
      return {
        getPropertyValue: () => "",
      };
    },
    matchMedia(query) {
      return {
        matches: false,
        media: String(query || ""),
        onchange: null,
        addEventListener() {},
        removeEventListener() {},
        addListener() {},
        removeListener() {},
        dispatchEvent: () => true,
      };
    },
    indexedDB: {
      open() {
        return {};
      },
    },
    createImageBitmap() {
      return Promise.resolve({});
    },
    chrome: { runtime: {} },
    trustedTypes: {},
    launchQueue: {},
    scheduler: {},
    Event: class Event {
      constructor(type) {
        this.type = type;
      }
    },
    requestIdleCallback(cb) {
      return setTimeout(() => cb({ timeRemaining: () => 50, didTimeout: false }), 0);
    },
    __sentinel_prop_trace: new Set(),
    __sentinel_vm_trace: [],
  };
  win.window = win;
  win.self = win;
  win.globalThis = win;
  if (!win.top) win.top = win;
  setToStringTag(win, "Window");
  return win;
}

function instrumentSdkForDebug(code) {
  const replacements = {
    'An()[r(29)]((t=>{n(btoa(kn+": "+t))}))':
      'An()[r(29)]((t=>{const __raw=kn+": "+t;window.__sentinel_vm_trace&&window.__sentinel_vm_trace.push({vm:"nested",kind:"final",raw_len:String(__raw).length,raw_hex_head:Array.from(String(__raw).slice(0,48),ch=>ch.charCodeAt(0).toString(16).padStart(2,"0")).join(""),raw_preview:String(__raw).slice(0,240),raw_b64_len:btoa(String(__raw)).length,raw_b64_head:btoa(String(__raw)).slice(0,80)});n(btoa(__raw))}))',
    'An()[o(29)]((t=>{e(btoa(kn+": "+t))}))':
      'An()[o(29)]((t=>{const __raw=kn+": "+t;window.__sentinel_vm_trace&&window.__sentinel_vm_trace.push({vm:"main",kind:"final",raw_len:String(__raw).length,raw_hex_head:Array.from(String(__raw).slice(0,48),ch=>ch.charCodeAt(0).toString(16).padStart(2,"0")).join(""),raw_preview:String(__raw).slice(0,240),raw_b64_len:btoa(String(__raw)).length,raw_b64_head:btoa(String(__raw)).slice(0,80)});e(btoa(__raw))}))',
    'try{bn[r(4)](Zt,JSON[r(14)](Tn(atob(t),""+bn[r(10)](en)))),':
      'try{const __key=""+bn[r(10)](en);const __decoded=Tn(atob(t),__key);window.__sentinel_vm_trace&&window.__sentinel_vm_trace.push({vm:"nested",kind:"decode",key_len:__key.length,decoded_len:__decoded.length,decoded_preview:__decoded.slice(0,160)});bn[r(4)](Zt,JSON[r(14)](__decoded)),',
    'try{bn[o(4)](Zt,JSON.parse(Tn(atob(n),""+bn[o(10)](en)))),':
      'try{const __key=""+bn[o(10)](en);const __decoded=Tn(atob(n),__key);window.__sentinel_vm_trace&&window.__sentinel_vm_trace.push({vm:"main",kind:"decode",key_len:__key.length,decoded_len:__decoded.length,decoded_preview:__decoded.slice(0,160)});bn[o(4)](Zt,JSON.parse(__decoded)),',
    'bn[r(4)](Jt,(t=>{!o&&(o=!0,n(btoa(""+t)))}))':
      'bn[r(4)](Jt,(t=>{!o&&(o=!0,window.__sentinel_vm_trace&&window.__sentinel_vm_trace.push({vm:"nested",kind:"opcode_return",raw_len:String(t).length,raw_hex_head:Array.from(String(t).slice(0,48),ch=>ch.charCodeAt(0).toString(16).padStart(2,"0")).join(""),raw_preview:String(t).slice(0,240),raw_b64_len:btoa(""+t).length,raw_b64_head:btoa(""+t).slice(0,80)}),n(btoa(""+t))) }))',
    'bn[r(4)](Gt,(t=>{!o&&(o=!0,e(btoa(""+t)))}))':
      'bn[r(4)](Gt,(t=>{!o&&(o=!0,window.__sentinel_vm_trace&&window.__sentinel_vm_trace.push({vm:"nested",kind:"opcode_error",raw_len:String(t).length,raw_hex_head:Array.from(String(t).slice(0,48),ch=>ch.charCodeAt(0).toString(16).padStart(2,"0")).join(""),raw_preview:String(t).slice(0,240),raw_b64_len:btoa(""+t).length,raw_b64_head:btoa(""+t).slice(0,80)}),e(btoa(""+t))) }))',
    'bn[o(4)](Jt,(t=>{!c&&(c=!0,e(btoa(""+t)))}))':
      'bn[o(4)](Jt,(t=>{!c&&(c=!0,window.__sentinel_vm_trace&&window.__sentinel_vm_trace.push({vm:"main",kind:"opcode_return",raw_len:String(t).length,raw_hex_head:Array.from(String(t).slice(0,48),ch=>ch.charCodeAt(0).toString(16).padStart(2,"0")).join(""),raw_preview:String(t).slice(0,240),raw_b64_len:btoa(""+t).length,raw_b64_head:btoa(""+t).slice(0,80)}),e(btoa(""+t))) }))',
    'bn[o(4)](Gt,(t=>{!c&&(c=!0,r(btoa(""+t)))}))':
      'bn[o(4)](Gt,(t=>{!c&&(c=!0,window.__sentinel_vm_trace&&window.__sentinel_vm_trace.push({vm:"main",kind:"opcode_error",raw_len:String(t).length,raw_hex_head:Array.from(String(t).slice(0,48),ch=>ch.charCodeAt(0).toString(16).padStart(2,"0")).join(""),raw_preview:String(t).slice(0,240),raw_b64_len:btoa(""+t).length,raw_b64_head:btoa(""+t).slice(0,80)}),r(btoa(""+t))) }))',
  };
  for (const [target, replacement] of Object.entries(replacements)) {
    if (!code.includes(target)) console.error("[debug] vm instrumentation target not found", target.slice(0, 80));
    code = code.replace(target, replacement);
  }

  const bindTarget =
    "bn[t(4)](Ht,((n,e,r)=>bn[t(4)](n,bn[t(10)](e)[bn[t(10)](r)][t(28)](bn.get(e)))))";
  const bindReplacement =
    "bn[t(4)](Ht,((n,e,r)=>{const obj=bn[t(10)](e),prop=bn[t(10)](r);window.__sentinel_prop_trace&&window.__sentinel_prop_trace.add('bind:'+String(prop)+':'+Object.prototype.toString.call(obj));if(!obj||!obj[prop]||!obj[prop][t(28)])throw new Error('Ht bind missing objReg='+e+' propReg='+r+' prop='+String(prop)+' objType='+Object.prototype.toString.call(obj));bn[t(4)](n,obj[prop][t(28)](obj))}))";
  const getTarget =
    "bn[t(4)](zt,((n,e,r)=>bn.set(n,bn[t(10)](e)[bn[t(10)](r)])))";
  const getReplacement =
    "bn[t(4)](zt,((n,e,r)=>{const obj=bn[t(10)](e),prop=bn[t(10)](r);window.__sentinel_prop_trace&&window.__sentinel_prop_trace.add('get:'+String(prop)+':'+Object.prototype.toString.call(obj));bn.set(n,obj[prop])}))";
  if (!code.includes(bindTarget)) {
    console.error("[debug] nested Ht instrumentation target not found");
  }
  if (!code.includes(getTarget)) {
    console.error("[debug] nested zt instrumentation target not found");
  }
  return code.replace(bindTarget, bindReplacement).replace(getTarget, getReplacement);
}

async function main() {
  const args = parseArgs(process.argv);
  const debug = (...items) => {
    if (args.debug) console.error("[debug]", ...items);
  };
  let sdkCode = "";
  if (args.sdkPath && fs.existsSync(args.sdkPath)) {
    sdkCode = fs.readFileSync(args.sdkPath, "utf8");
  } else {
    const response = await fetch(SDK_URL);
    if (!response.ok) throw new Error(`failed to fetch Sentinel SDK: ${response.status}`);
    sdkCode = await response.text();
  }
  if (args.debug) sdkCode = instrumentSdkForDebug(sdkCode);
  const cookie = args.cookieHeader || `oai-did=${args.deviceId}`;
  const fetchCookie = args.fetchCookieHeader !== null ? args.fetchCookieHeader : cookie;
  const sentinelReqSetCookies = [];

  const mainWindow = createWindow({
    href: args.pageUrl || "https://auth.openai.com/create-account",
    currentScriptUrl: SDK_URL,
    cookie,
    options: args,
  });
  const frameWindow = createWindow({
    href: FRAME_URL,
    currentScriptUrl: SDK_URL,
    cookie,
    topWindow: mainWindow,
    options: args,
  });

  frameWindow.postMessage = (data, origin) => {
    debug("main->frame", data?.type, data?.flow, data?.requestId);
    setTimeout(() => {
      frameWindow.__dispatch("message", {
        data,
        origin: origin || "https://sentinel.openai.com",
        source: mainWindow,
      });
    }, 0);
  };
  const originalMainBodyAppendChild = mainWindow.document.body.appendChild.bind(mainWindow.document.body);
  mainWindow.document.body.appendChild = (node) => {
    if (String(node?.tagName || "").toUpperCase() === "IFRAME") {
      node.contentWindow = frameWindow;
    }
    originalMainBodyAppendChild(node);
    debug("append child", node.tagName || "", node.src || "");
    setTimeout(() => {
      debug("child load fired", node.tagName || "", typeof node.onload);
      if (typeof node.onload === "function") node.onload();
    }, 0);
  };
  mainWindow.postMessage = (data, options) => {
    debug("frame->main", data?.type, data?.requestId, data?.error ? "error" : "ok");
    const origin = typeof options === "string" ? options : options?.targetOrigin || "https://sentinel.openai.com";
    setTimeout(() => {
      mainWindow.__dispatch("message", {
        data,
        origin,
        source: frameWindow,
      });
    }, 0);
  };

  frameWindow.fetch = async (url, options = {}) => {
    debug("fetch", String(url));
    const headers = {
      "content-type": "text/plain;charset=UTF-8",
      origin: "https://sentinel.openai.com",
      referer: FRAME_URL,
      cookie: fetchCookie,
      ...(options.headers || {}),
    };
    const response = await fetch(url, { ...options, headers });
    if (String(url).includes("/backend-api/sentinel/req")) {
      let setCookies = [];
      try {
        setCookies = response.headers.getSetCookie();
      } catch {
        const rawSetCookie = response.headers.get("set-cookie");
        setCookies = rawSetCookie ? [rawSetCookie] : [];
      }
      for (const item of setCookies || []) {
        const text = String(item || "").trim();
        if (text) sentinelReqSetCookies.push(text);
      }
    }
    if (args.dumpReq && String(url).includes("/backend-api/sentinel/req")) {
      const text = await response.clone().text();
      let body = {};
      try {
        body = JSON.parse(String(options.body || "{}"));
      } catch {
        body = { rawBody: String(options.body || "") };
      }
      const dump = {
        url: String(url),
        request: body,
        response: JSON.parse(text),
      };
      fs.writeFileSync(args.dumpReq, JSON.stringify(dump, null, 2));
    }
    return response;
  };
  mainWindow.fetch = frameWindow.fetch;

  vm.createContext(frameWindow);
  vm.runInContext(sdkCode, frameWindow, { filename: "sentinel-sdk-frame.js" });
  vm.createContext(mainWindow);
  vm.runInContext(sdkCode, mainWindow, { filename: "sentinel-sdk-main.js" });
  if (args.debug) {
    const originalError = console.error;
    frameWindow.console = {
      ...console,
      log: (...items) => originalError("[frame log]", ...items),
      warn: (...items) => originalError("[frame warn]", ...items),
      error: (...items) => originalError("[frame error]", ...items),
    };
    mainWindow.console = {
      ...console,
      log: (...items) => originalError("[main log]", ...items),
      warn: (...items) => originalError("[main warn]", ...items),
      error: (...items) => originalError("[main error]", ...items),
    };
  }
  debug("sdk loaded", typeof mainWindow.SentinelSDK, Object.keys(mainWindow.SentinelSDK || {}));

  const tokenText = await Promise.race([
    mainWindow.SentinelSDK.token(args.flow),
    new Promise((_, reject) => setTimeout(() => reject(new Error("token timeout")), 30000)),
  ]);
  const soTokenText = args.withSo
    ? await Promise.race([
        mainWindow.SentinelSDK.sessionObserverToken(args.flow),
        new Promise((_, reject) => setTimeout(() => reject(new Error("session observer token timeout")), 30000)),
      ])
    : null;
  let parsed = null;
  try {
    parsed = JSON.parse(tokenText);
  } catch (err) {
    parsed = { parse_error: String(err), raw_length: tokenText.length };
  }
  let soParsed = null;
  try {
    soParsed = soTokenText ? JSON.parse(soTokenText) : null;
  } catch (err) {
    soParsed = { parse_error: String(err), raw_length: String(soTokenText || "").length };
  }

  if (args.full) {
    if (args.bundleOutput || args.withSo) {
      console.log(
        JSON.stringify({
          token: tokenText,
          session_observer_token: soTokenText || "",
          sentinel_req_set_cookies: sentinelReqSetCookies,
        }),
      );
    } else {
      console.log(tokenText);
    }
    setImmediate(() => process.exit(0));
    return;
  }

  let tDecoded = "";
  let tDecodedBuffer = Buffer.alloc(0);
  try {
    tDecodedBuffer = parsed?.t ? Buffer.from(String(parsed.t), "base64") : Buffer.alloc(0);
    tDecoded = tDecodedBuffer.toString("utf8");
  } catch {
    tDecoded = "";
    tDecodedBuffer = Buffer.alloc(0);
  }
  const printableRatio = tDecodedBuffer.length
    ? Array.from(tDecodedBuffer).filter((item) => item === 9 || item === 10 || item === 13 || (item >= 32 && item < 127))
        .length / tDecodedBuffer.length
    : 0;

  const summary = {
    flow: args.flow,
    device_id: args.deviceId,
    token_length: tokenText.length,
    keys: parsed && typeof parsed === "object" ? Object.keys(parsed).sort() : [],
    p_len: String(parsed?.p || "").length,
    t_len: String(parsed?.t || "").length,
    c_len: String(parsed?.c || "").length,
    so_token_length: String(soTokenText || "").length,
    so_keys: soParsed && typeof soParsed === "object" ? Object.keys(soParsed).sort() : [],
    so_len: String(soParsed?.so || "").length,
    so_c_len: String(soParsed?.c || "").length,
    has_id: Boolean(parsed?.id),
    has_error: Boolean(parsed?.e),
    error: parsed?.e ? String(parsed.e).slice(0, 200) : "",
    sentinel_req_set_cookie_count: sentinelReqSetCookies.length,
    sentinel_req_set_cookie_names: sentinelReqSetCookies
      .map((item) => String(item || "").split("=", 1)[0].trim())
      .filter(Boolean),
    t_decoded_len: tDecodedBuffer.length,
    t_decoded_hex_head: tDecodedBuffer.slice(0, 48).toString("hex"),
    t_decoded_printable_ratio: Number(printableRatio.toFixed(3)),
    t_decoded_preview: tDecoded.slice(0, 80),
    prop_trace:
      args.debug && mainWindow.__sentinel_prop_trace
        ? Array.from(mainWindow.__sentinel_prop_trace).sort().slice(0, 200)
        : undefined,
    vm_trace: args.debug && mainWindow.__sentinel_vm_trace ? mainWindow.__sentinel_vm_trace.slice(0, 20) : undefined,
  };
  const summaryText = JSON.stringify(summary, null, 2);
  if (args.out) fs.writeFileSync(args.out, summaryText + "\n", "utf8");
  console.log(summaryText);
  setImmediate(() => process.exit(0));
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exitCode = 1;
});
