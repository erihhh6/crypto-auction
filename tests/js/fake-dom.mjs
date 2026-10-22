// A small stand-in for the browser DOM, enough to run static/app.js in Node
// without dependencies: elements with children, text, classes, events and
// focus, in a document holding the elements of the real index.html.
//
// It follows the DOM rules the page relies on: a node has one parent (adding
// it elsewhere moves it), setting textContent replaces the children, and
// removing the focused element (or an ancestor of it) drops the focus.

import { readFileSync } from "node:fs";

const INDEX_HTML = readFileSync(
  new URL("../../src/crypto_auction/web/templates/index.html", import.meta.url),
  "utf8",
);
// Every element of the page with an id, so getElementById finds what the
// page has, and only that; hidden as the page starts, if it says so.
const PAGE_ELEMENTS = [...INDEX_HTML.matchAll(/<[^>]*\sid="([^"]+)"[^>]*>/g)].map((m) => ({
  id: m[1],
  hidden: /\shidden[\s/>]/.test(m[0]),
}));

class FakeClassList {
  constructor(element) {
    this.element = element;
  }
  names() {
    return this.element.className.split(/\s+/).filter(Boolean);
  }
  contains(name) {
    return this.names().includes(name);
  }
  add(...names) {
    this.element.className = [...new Set([...this.names(), ...names])].join(" ");
  }
  remove(...names) {
    this.element.className = this.names()
      .filter((n) => !names.includes(n))
      .join(" ");
  }
  toggle(name, force = !this.contains(name)) {
    if (force) this.add(name);
    else this.remove(name);
    return force;
  }
}

export class FakeElement {
  constructor(document, tagName) {
    this.ownerDocument = document;
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.id = "";
    this.className = "";
    this.classList = new FakeClassList(this);
    this.dataset = {};
    this.style = {};
    this.value = "";
    this.disabled = false;
    this.hidden = false;
    this.open = false;
    this.title = "";
    this.listeners = {};
    this.attributes = new Map();
    this.ownText = "";
    this.html = "";
    this.innerHTMLWrites = 0;
  }

  get textContent() {
    return this.ownText + this.children.map((c) => c.textContent).join("");
  }
  set textContent(text) {
    this.removeAllChildren();
    this.html = "";
    this.ownText = String(text);
  }
  // Stored, not parsed (so it adds no children and no text): the tests read
  // back the markup that was written.
  get innerHTML() {
    return this.html;
  }
  set innerHTML(html) {
    this.removeAllChildren();
    this.ownText = "";
    this.html = String(html);
    this.innerHTMLWrites += 1;
    this.ownerDocument.markupWritten.push(this.html);
  }

  get firstElementChild() {
    return this.children[0] ?? null;
  }
  get lastElementChild() {
    return this.children.at(-1) ?? null;
  }

  insertBefore(node, reference) {
    node.remove(); // a node has one parent
    const index = reference === null ? this.children.length : this.children.indexOf(reference);
    if (index < 0) throw new Error("insertBefore: the reference node is not a child");
    this.children.splice(index, 0, node);
    node.parentNode = this;
    return node;
  }
  appendChild(node) {
    return this.insertBefore(node, null);
  }
  append(...nodes) {
    for (const node of nodes) this.insertBefore(node, null);
  }
  prepend(node) {
    this.insertBefore(node, this.firstElementChild);
  }
  replaceChildren(...nodes) {
    this.removeAllChildren();
    this.append(...nodes);
  }
  removeAllChildren() {
    for (const child of [...this.children]) child.remove();
  }
  remove() {
    if (this.parentNode === null) return;
    const document = this.ownerDocument;
    if (this.contains(document.activeElement)) document.activeElement = document.body;
    this.parentNode.children.splice(this.parentNode.children.indexOf(this), 1);
    this.parentNode = null;
  }
  contains(node) {
    for (let n = node; n; n = n.parentNode) if (n === this) return true;
    return false;
  }
  get isConnected() {
    return this.ownerDocument.body.contains(this);
  }
  *descendants() {
    for (const child of this.children) {
      yield child;
      yield* child.descendants();
    }
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    this.ownerDocument.attributesSet.push(name);
  }
  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }
  removeAttribute(name) {
    this.attributes.delete(name);
  }

  // A <dialog>: closing it fires "close", as the browser's does. `modal`
  // tells showModal() (focus trapped, page inert) from show() (neither).
  show() {
    this.open = true;
    this.modal = false;
  }
  showModal() {
    this.open = true;
    this.modal = true;
  }
  close() {
    this.open = false;
    for (const listener of this.listeners.close ?? []) listener();
  }

  addEventListener(type, listener) {
    (this.listeners[type] ??= []).push(listener);
  }
  // Runs the click listeners and, unlike the browser, returns a promise for
  // what they return, so a test can wait for the request a click starts.
  click() {
    return Promise.all((this.listeners.click ?? []).map((listener) => listener()));
  }
  focus() {
    this.ownerDocument.activeElement = this;
  }
  select() {
    this.selected = true;
  }
}

/**
 * A document with the page's elements; `overrides` replace its methods.
 * `hidden` and `listeners` (by event type) stand for the page's visibility;
 * `markupWritten` and `attributesSet` record what the script put into it.
 */
export function fakeDocument(overrides = {}) {
  const document = {
    querySelectorAll: () => [],
    hidden: false,
    listeners: {},
    markupWritten: [],
    attributesSet: [],
  };
  document.addEventListener = (type, listener) => (document.listeners[type] ??= []).push(listener);
  document.createElement = (tag) => new FakeElement(document, tag);
  document.body = document.createElement("body");
  document.activeElement = document.body;
  for (const { id, hidden } of PAGE_ELEMENTS) {
    const element = document.createElement("div");
    element.id = id;
    element.hidden = hidden;
    document.body.append(element);
  }
  document.getElementById = (id) => {
    for (const node of document.body.descendants()) if (node.id === id) return node;
    return null;
  };
  return Object.assign(document, overrides);
}
