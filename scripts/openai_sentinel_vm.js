const fs = require("fs");
const { performance: nodePerformance } = require("node:perf_hooks");
const { webcrypto } = require("node:crypto");

const EXPOSE_PATCH = "return o?r?.[n(63)]?ce({so:o,c:r[n(63)]},t):o:null},t.token=ye,t}({});";
const EXPOSE_REPLACEMENT =
  "return o?r?.[n(63)]?ce({so:o,c:r[n(63)]},t):o:null},t.token=ye,t.__debug_n=_n,t.__debug_bindProof=D,t}({});";
const INSTANCE_PATCH = "var P=new _;";
const INSTANCE_REPLACEMENT = "var P=new _;globalThis.__debugP=P;";
const SDK_GLOBAL_PATCH = "var SentinelSDK=";
const SDK_GLOBAL_REPLACEMENT = "globalThis.SentinelSDK=";

function noop() {}

class StorageShim {
  constructor() {
    this.map = new Map();
  }

  get length() {
    return this.map.size;
  }

  key(index) {
    return Array.from(this.map.keys())[index] ?? null;
  }

  getItem(key) {
    const normalized = String(key);
    return this.map.has(normalized) ? this.map.get(normalized) : null;
  }

  setItem(key, value) {
    this.map.set(String(key), String(value));
  }

  removeItem(key) {
    this.map.delete(String(key));
  }

  clear() {
    this.map.clear();
  }
}

class EventTargetShim {
  constructor() {
    this.listeners = new Map();
  }

  addEventListener(type, listener) {
    if (!listener) {
      return;
    }
    const key = String(type);
    const handlers = this.listeners.get(key) || new Set();
    handlers.add(listener);
    this.listeners.set(key, handlers);
  }

  removeEventListener(type, listener) {
    const key = String(type);
    const handlers = this.listeners.get(key);
    if (!handlers) {
      return;
    }
    handlers.delete(listener);
    if (!handlers.size) {
      this.listeners.delete(key);
    }
  }

  dispatchEvent(event) {
    if (!event || !event.type) {
      return true;
    }
    const handlers = this.listeners.get(String(event.type));
    if (!handlers) {
      return true;
    }
    for (const handler of handlers) {
      try {
        handler.call(this, event);
      } catch (_) {}
    }
    return true;
  }
}

function parseBrands(secChUa) {
  const raw = String(secChUa || "");
  const matches = Array.from(raw.matchAll(/"([^"]+)"\s*;\s*v="([^"]+)"/g));
  if (!matches.length) {
    return [
      { brand: "Chromium", version: "146" },
      { brand: "Google Chrome", version: "146" },
      { brand: "Not-A.Brand", version: "24" },
    ];
  }
  return matches.map((match) => ({ brand: match[1], version: match[2] }));
}

function createLocation(urlString) {
  let current = new URL(urlString);
  return {
    get href() {
      return current.href;
    },
    set href(value) {
      current = new URL(String(value), current.href);
    },
    get origin() {
      return current.origin;
    },
    get protocol() {
      return current.protocol;
    },
    get host() {
      return current.host;
    },
    get hostname() {
      return current.hostname;
    },
    get port() {
      return current.port;
    },
    get pathname() {
      return current.pathname;
    },
    get search() {
      return current.search;
    },
    get hash() {
      return current.hash;
    },
    assign(value) {
      this.href = value;
    },
    replace(value) {
      this.href = value;
    },
    reload: noop,
    toString() {
      return current.href;
    },
  };
}

function createStubElement(tagName, documentRef) {
  const attrs = new Map();
  const element = new EventTargetShim();
  element.tagName = String(tagName || "div").toUpperCase();
  element.nodeName = element.tagName;
  element.ownerDocument = documentRef;
  element.children = [];
  element.childNodes = element.children;
  element.style = {};
  element.dataset = {};
  element.parentNode = null;
  element.hidden = false;
  element.disabled = false;
  element.value = "";
  element.innerHTML = "";
  element.textContent = "";
  element.width = 0;
  element.height = 0;
  element.src = "";
  element.href = "";
  element.setAttribute = (name, value) => {
    const key = String(name);
    const normalized = String(value);
    attrs.set(key, normalized);
    element[key] = normalized;
  };
  element.getAttribute = (name) => attrs.get(String(name)) ?? null;
  element.removeAttribute = (name) => {
    const key = String(name);
    attrs.delete(key);
    delete element[key];
  };
  element.appendChild = (child) => {
    if (child) {
      child.parentNode = element;
      element.children.push(child);
    }
    return child;
  };
  element.removeChild = (child) => {
    const index = element.children.indexOf(child);
    if (index >= 0) {
      element.children.splice(index, 1);
    }
    return child;
  };
  element.cloneNode = () => createStubElement(tagName, documentRef);
  element.getContext = () => null;
  element.toDataURL = () => "";
  element.querySelector = () => null;
  element.querySelectorAll = () => [];
  element.getBoundingClientRect = () => ({
    x: 0,
    y: 0,
    width: 0,
    height: 0,
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
  });
  element.focus = noop;
  element.blur = noop;
  element.click = noop;
  return element;
}

function createDocument(location, payload) {
  const cookieMap = new Map();
  const documentRef = new EventTargetShim();
  const documentElement = createStubElement("html", documentRef);
  const head = createStubElement("head", documentRef);
  const body = createStubElement("body", documentRef);
  documentElement.appendChild(head);
  documentElement.appendChild(body);

  Object.defineProperty(documentRef, "cookie", {
    configurable: true,
    get() {
      return Array.from(cookieMap.entries())
        .map(([name, value]) => `${name}=${value}`)
        .join("; ");
    },
    set(value) {
      const raw = String(value || "");
      const firstPart = raw.split(";", 1)[0];
      const separator = firstPart.indexOf("=");
      if (separator <= 0) {
        return;
      }
      const name = firstPart.slice(0, separator).trim();
      const cookieValue = firstPart.slice(separator + 1).trim();
      cookieMap.set(name, cookieValue);
    },
  });

  documentRef.documentElement = documentElement;
  documentRef.head = head;
  documentRef.body = body;
  documentRef.readyState = "complete";
  documentRef.hidden = false;
  documentRef.visibilityState = "visible";
  documentRef.referrer = "https://auth.openai.com/";
  documentRef.location = location;
  documentRef.URL = location.href;
  documentRef.baseURI = location.href;
  documentRef.documentURI = location.href;
  documentRef.hasFocus = () => true;
  documentRef.createElement = (tagName) => createStubElement(tagName, documentRef);
  documentRef.createTextNode = (text) => ({ nodeValue: String(text || ""), textContent: String(text || "") });
  documentRef.querySelector = (selector) => {
    if (selector === "head") {
      return head;
    }
    if (selector === "body") {
      return body;
    }
    if (selector === "html") {
      return documentElement;
    }
    if (selector === "script") {
      return documentRef.currentScript;
    }
    return null;
  };
  documentRef.querySelectorAll = () => [];
  documentRef.getElementsByTagName = (tagName) => {
    const normalized = String(tagName || "").toLowerCase();
    if (normalized === "script") {
      return documentRef.scripts;
    }
    if (normalized === "head") {
      return [head];
    }
    if (normalized === "body") {
      return [body];
    }
    if (normalized === "html") {
      return [documentElement];
    }
    return [];
  };

  const currentScript = createStubElement("script", documentRef);
  currentScript.src = `https://sentinel.openai.com/sentinel/${payload.sentinel_version || "sdk"}/sdk.js`;
  documentRef.currentScript = currentScript;
  documentRef.scripts = [currentScript];

  return documentRef;
}

function createNavigator(payload) {
  const brands = parseBrands(payload.sec_ch_ua);
  return {
    userAgent: String(payload.user_agent || ""),
    language: String(payload.language || "en-US"),
    languages: Array.isArray(payload.languages) ? payload.languages : ["en-US", "en"],
    hardwareConcurrency: Number(payload.hardware_concurrency || 12),
    cookieEnabled: true,
    onLine: true,
    webdriver: false,
    vendor: "Google Inc.",
    platform: "Win32",
    maxTouchPoints: 0,
    deviceMemory: 8,
    pdfViewerEnabled: true,
    plugins: [],
    mimeTypes: [],
    userAgentData: {
      brands,
      mobile: false,
      platform: "Windows",
      getHighEntropyValues: async () => ({
        architecture: "x86",
        bitness: "64",
        brands,
        mobile: false,
        model: "",
        platform: "Windows",
        platformVersion: "10.0.0",
        uaFullVersion: "146.0.0.0",
      }),
    },
    connection: {
      effectiveType: "4g",
      rtt: 50,
      downlink: 10,
      saveData: false,
    },
    permissions: {
      query: async () => ({ state: "prompt" }),
    },
    mediaDevices: {
      enumerateDevices: async () => [],
    },
    clipboard: {
      readText: async () => "",
      writeText: async () => undefined,
    },
    locks: {},
    ink: {},
    scheduling: {
      isInputPending: () => false,
    },
    credentials: {},
  };
}

function createWindow(payload) {
  const location = createLocation("https://auth.openai.com/");
  const documentRef = createDocument(location, payload);
  const localStorage = new StorageShim();
  const sessionStorage = new StorageShim();
  const performance = {
    now: () => Number(payload.performance_now || 12345.67),
    timeOrigin: Number(payload.time_origin || Date.now() - 12345.67),
    memory: {
      jsHeapSizeLimit: Number(payload.js_heap_size_limit || 4294967296),
    },
    mark: (...args) => nodePerformance.mark?.(...args),
    measure: (...args) => nodePerformance.measure?.(...args),
    clearMarks: (...args) => nodePerformance.clearMarks?.(...args),
    clearMeasures: (...args) => nodePerformance.clearMeasures?.(...args),
    eventCounts: nodePerformance.eventCounts || new Map(),
  };
  const screen = {
    width: Number(payload.screen_width || 1366),
    height: Number(payload.screen_height || 768),
    availWidth: Number(payload.screen_width || 1366),
    availHeight: Number(payload.screen_height || 768),
    colorDepth: 24,
    pixelDepth: 24,
  };
  const history = {
    length: 1,
    state: null,
    pushState: noop,
    replaceState: noop,
  };

  const windowRef = new EventTargetShim();
  windowRef.window = windowRef;
  windowRef.self = windowRef;
  windowRef.top = windowRef;
  windowRef.parent = windowRef;
  windowRef.frames = [];
  windowRef.frameElement = null;
  windowRef.document = documentRef;
  windowRef.localStorage = localStorage;
  windowRef.sessionStorage = sessionStorage;
  windowRef.location = location;
  windowRef.navigator = createNavigator({ ...payload, sec_ch_ua: payload.sec_ch_ua || "" });
  windowRef.performance = performance;
  windowRef.screen = screen;
  windowRef.history = history;
  windowRef.innerWidth = screen.width;
  windowRef.innerHeight = screen.height;
  windowRef.outerWidth = screen.width;
  windowRef.outerHeight = screen.height;
  windowRef.devicePixelRatio = 1;
  windowRef.isSecureContext = true;
  windowRef.crypto = globalThis.crypto || webcrypto;
  windowRef.setTimeout = setTimeout.bind(globalThis);
  windowRef.clearTimeout = clearTimeout.bind(globalThis);
  windowRef.setInterval = setInterval.bind(globalThis);
  windowRef.clearInterval = clearInterval.bind(globalThis);
  windowRef.queueMicrotask = queueMicrotask.bind(globalThis);
  windowRef.requestAnimationFrame = (callback) =>
    windowRef.setTimeout(() => callback(performance.now()), 16);
  windowRef.cancelAnimationFrame = (handle) => windowRef.clearTimeout(handle);
  windowRef.requestIdleCallback = (callback) =>
    windowRef.setTimeout(() => callback({ didTimeout: false, timeRemaining: () => 50 }), 0);
  windowRef.cancelIdleCallback = (handle) => windowRef.clearTimeout(handle);
  windowRef.matchMedia = (query) => ({
    matches: false,
    media: String(query || ""),
    addListener: noop,
    removeListener: noop,
    addEventListener: noop,
    removeEventListener: noop,
    dispatchEvent: () => false,
  });
  windowRef.getComputedStyle = () => ({
    getPropertyValue: () => "",
  });
  windowRef.fetch = async () => {
    throw new Error("fetch should not be called");
  };

  documentRef.defaultView = windowRef;
  documentRef.cookie = `oai-did=${encodeURIComponent(payload.device_id || "")}`;

  return windowRef;
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function prepareWindow(payload) {
  const windowRef = createWindow(payload);
  global.window = windowRef;
  global.document = windowRef.document;
  global.self = windowRef;
  global.localStorage = windowRef.localStorage;
  global.sessionStorage = windowRef.sessionStorage;
  global.screen = windowRef.screen;
  global.performance = windowRef.performance;
  global.crypto = windowRef.crypto;
  global.atob = (input) => Buffer.from(input, "base64").toString("binary");
  global.btoa = (input) => Buffer.from(input, "binary").toString("base64");
  global.fetch = windowRef.fetch;
  global.history = windowRef.history;
  Object.defineProperty(global, "navigator", {
    value: windowRef.navigator,
    configurable: true,
  });
  Object.defineProperty(global, "location", {
    value: windowRef.location,
    configurable: true,
  });
}

function loadSdk(payload) {
  let sdk = fs.readFileSync(payload.sdk_path, "utf8");
  sdk = sdk.replace(SDK_GLOBAL_PATCH, SDK_GLOBAL_REPLACEMENT);
  sdk = sdk.replace(INSTANCE_PATCH, INSTANCE_REPLACEMENT);
  sdk = sdk.replace(EXPOSE_PATCH, EXPOSE_REPLACEMENT);
  eval(sdk);
}

async function run(payload) {
  prepareWindow(payload);
  loadSdk(payload);

  if (payload.action === "requirements") {
    const requestP = await globalThis.__debugP.getRequirementsToken();
    return { request_p: requestP };
  }

  if (payload.action === "solve") {
    const challenge = payload.challenge || {};
    const requestP = String(payload.request_p || "").trim();
    if (!requestP) {
      throw new Error("missing request_p");
    }
    const finalP = await globalThis.__debugP.getEnforcementToken(challenge);
    global.SentinelSDK.__debug_bindProof(challenge, requestP);
    const dx = challenge?.turnstile?.dx;
    const tValue = dx ? await global.SentinelSDK.__debug_n(challenge, dx) : null;
    return {
      final_p: finalP,
      t: tValue,
    };
  }

  throw new Error(`unsupported action: ${payload.action}`);
}

(async () => {
  try {
    const raw = await readStdin();
    const payload = JSON.parse(raw || "{}");
    const result = await run(payload);
    process.stdout.write(JSON.stringify(result));
  } catch (error) {
    const message = error && error.stack ? error.stack : String(error);
    process.stderr.write(message);
    process.exit(1);
  }
})();
