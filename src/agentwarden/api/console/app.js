// AgentWarden approver console.
//
// Everything shown here can contain attacker-controlled text (tool arguments, injected email
// content, evidence snippets). The page therefore never parses data as HTML: every value is placed
// with textContent / DOM nodes, and the server sends a CSP that forbids inline script.
"use strict";

(function () {
  const REFRESH_MS = 5000;
  const STORE_KEY = "agentwarden.console";
  const state = { method: "key", credential: null, me: null, tab: "pending", timer: null };
  const cards = new Map(); // approval id -> card element (keeps typed notes across refreshes)

  const $ = (id) => document.getElementById(id);

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value === undefined || value === null) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = String(value);
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, String(value));
    }
    for (const child of children) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  // ------------------------------------------------------------------ session
  function saveSession() {
    try {
      sessionStorage.setItem(STORE_KEY, JSON.stringify({ method: state.method, credential: state.credential }));
    } catch (_) { /* storage unavailable: stay signed in for this page view only */ }
  }

  function loadSession() {
    try {
      const raw = sessionStorage.getItem(STORE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  }

  function clearSession() {
    try { sessionStorage.removeItem(STORE_KEY); } catch (_) { /* ignore */ }
  }

  function authHeaders() {
    return state.method === "key"
      ? { "X-API-Key": state.credential }
      : { Authorization: "Bearer " + state.credential };
  }

  async function api(path, options) {
    const response = await fetch(path, {
      method: (options && options.method) || "GET",
      headers: Object.assign({ "Content-Type": "application/json" }, authHeaders()),
      body: options && options.body ? JSON.stringify(options.body) : undefined,
      credentials: "omit",
      cache: "no-store",
    });
    let body = null;
    try { body = await response.json(); } catch (_) { /* empty body */ }
    if (!response.ok) {
      const message = (body && (body.detail || body.error_description)) || response.statusText;
      const error = new Error(typeof message === "string" ? message : "Request failed");
      error.status = response.status;
      throw error;
    }
    return body;
  }

  // ------------------------------------------------------------------ formatting
  function timeLeft(iso) {
    const seconds = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
    if (seconds <= 0) return "expired";
    if (seconds < 90) return seconds + "s left";
    return Math.round(seconds / 60) + " min left";
  }

  function ago(iso) {
    const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
    if (seconds < 60) return "just now";
    if (seconds < 3600) return Math.round(seconds / 60) + " min ago";
    return new Date(iso).toLocaleString();
  }

  function riskLevel(approval) {
    const details = approval.details || {};
    if (details.risk_level) return details.risk_level;
    const score = approval.risk_score;
    return score >= 0.85 ? "critical" : score >= 0.6 ? "high" : score >= 0.3 ? "medium" : "low";
  }

  function toast(message) {
    const node = $("toast");
    node.textContent = message;
    node.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { node.hidden = true; }, 4000);
  }

  // ------------------------------------------------------------------ cards
  function block(title, content, wide) {
    return el("div", { class: "block" + (wide ? " wide" : "") }, el("span", { class: "label", text: title }), content);
  }

  function signalList(signals) {
    if (!signals || signals.length === 0) return el("p", { class: "muted", text: "No risk signals." });
    return el(
      "div",
      { class: "signals" },
      ...signals.map((s) =>
        el(
          "div",
          { class: "signal" },
          el(
            "div",
            {},
            el("div", { class: "name", text: s.name + " (" + Number(s.weight).toFixed(2) + ")" }),
            el("div", { class: "meter", "aria-hidden": "true" }, meter(s.weight)),
          ),
          el("div", { class: "evidence", text: (s.evidence || "") + (s.location ? "  [" + s.location + "]" : "") }),
        ),
      ),
    );
  }

  function meter(weight) {
    const fill = el("span");
    fill.style.width = Math.round(Math.max(0, Math.min(1, Number(weight))) * 100) + "%";
    return fill;
  }

  function buildCard(approval) {
    const details = approval.details || {};
    const level = riskLevel(approval);
    const chain = (details.actor_chain || [approval.agent_id]).join(" → ");
    const expires = el("span", { class: "chip", "data-expires": approval.expires_at, text: timeLeft(approval.expires_at) });

    const head = el(
      "div",
      { class: "card-head" },
      el(
        "div",
        {},
        el("div", { class: "tool", text: approval.tool }),
        el("div", { class: "sub", text: "Agent " + chain + " for " + approval.user_id + " · " + ago(approval.created_at) }),
      ),
      el(
        "div",
        { class: "chips" },
        el("span", { class: "chip " + level, text: level + " risk " + Number(approval.risk_score).toFixed(2) }),
        el("span", { class: "chip status-" + approval.status, text: approval.status }),
        approval.status === "pending" ? expires : null,
      ),
    );

    const body = el(
      "div",
      { class: "body" },
      block("The user asked", el("p", { class: "quote", text: details.user_prompt || "(not provided by the agent)" })),
      block("Why it needs a human", el("ul", { class: "reasons" }, ...(approval.reasons || []).map((r) => el("li", { text: r })))),
      block("Risk evidence", signalList(details.signals), true),
      block("Arguments (secrets redacted)", el("pre", { class: "args", text: JSON.stringify(approval.args_preview, null, 2) }), true),
      block(
        "Content the agent had read",
        (details.context_sources || []).length
          ? el("div", { class: "chips" }, ...details.context_sources.map((s) => el("span", { class: "chip", text: s })))
          : el("p", { class: "muted", text: "None reported" }),
        true,
      ),
    );

    const card = el("article", { class: "card risk-" + level, "data-id": approval.id, "aria-label": approval.tool + " request" }, head, body);
    card.append(approval.status === "pending" ? actions(approval) : reviewed(approval));
    return card;
  }

  function reviewed(approval) {
    const who = approval.reviewer ? "by " + approval.reviewer : "";
    const note = approval.note ? " · “" + approval.note + "”" : "";
    return el("div", { class: "reviewed", text: approval.status + " " + who + note });
  }

  function actions(approval) {
    const own = state.me && approval.user_id === state.me.id;
    const noteId = "note-" + approval.id;
    const note = el("input", { type: "text", id: noteId, placeholder: "Note (optional)", maxlength: "1000", "aria-label": "Note" });
    const approve = el("button", { type: "button", class: "approve", text: "Approve" });
    const deny = el("button", { type: "button", class: "deny", text: "Deny" });
    const bar = el("div", { class: "actions" }, note, approve, deny);
    if (own || !state.me || !state.me.approver) {
      note.disabled = approve.disabled = deny.disabled = true;
      bar.append(el("span", { class: "why", text: own ? "You can't review a request made on your behalf." : "Approver role required." }));
      return bar;
    }
    const decide = async (verb) => {
      approve.disabled = deny.disabled = true;
      try {
        await api("/v1/approvals/" + encodeURIComponent(approval.id) + "/" + verb, { method: "POST", body: { note: note.value } });
        toast(verb === "approve" ? "Approved. The agent can retry the exact same call once." : "Denied. The agent's call will be refused.");
        await refresh();
      } catch (error) {
        toast(error.message);
        approve.disabled = deny.disabled = false;
      }
    };
    approve.addEventListener("click", () => decide("approve"));
    deny.addEventListener("click", () => decide("deny"));
    return bar;
  }

  // ------------------------------------------------------------------ rendering
  function render(approvals) {
    const list = $("list");
    const wanted = new Set(approvals.map((a) => a.id + ":" + a.status));
    for (const [key, card] of cards) {
      if (!wanted.has(key)) { card.remove(); cards.delete(key); }
    }
    let previous = null;
    for (const approval of approvals) {
      const key = approval.id + ":" + approval.status;
      let card = cards.get(key);
      if (!card) { card = buildCard(approval); cards.set(key, card); }
      if (previous ? previous.nextSibling !== card : list.firstChild !== card) {
        if (previous) previous.after(card); else list.prepend(card);
      }
      previous = card;
    }
    for (const chip of list.querySelectorAll("[data-expires]")) chip.textContent = timeLeft(chip.getAttribute("data-expires"));
    $("empty").hidden = approvals.length > 0;
  }

  async function refresh() {
    if (!state.me || !state.me.approver) return;
    try {
      const all = await api("/v1/approvals?limit=200");
      const pending = all.filter((a) => a.status === "pending");
      $("pending-count").textContent = String(pending.length);
      render(state.tab === "pending" ? pending : all.filter((a) => a.status !== "pending").slice(0, 50));
      $("refreshed").textContent = "Updated " + new Date().toLocaleTimeString();
    } catch (error) {
      if (error.status === 401) { signOut("Your session expired. Sign in again."); return; }
      $("refreshed").textContent = "Couldn't refresh: " + error.message;
    }
  }

  function selectTab(tab) {
    state.tab = tab;
    $("tab-pending").setAttribute("aria-selected", String(tab === "pending"));
    $("tab-history").setAttribute("aria-selected", String(tab === "history"));
    for (const card of cards.values()) card.remove();
    cards.clear();
    refresh();
  }

  // ------------------------------------------------------------------ sign-in
  async function signIn(method, credential, quiet) {
    state.method = method;
    state.credential = credential;
    try {
      state.me = await api("/v1/me");
    } catch (error) {
      state.credential = null;
      clearSession();
      if (!quiet) {
        const box = $("signin-error");
        box.textContent = error.status === 401 ? "That credential wasn't accepted." : error.message;
        box.hidden = false;
      }
      return;
    }
    saveSession();
    $("signin").hidden = true;
    $("workspace").hidden = false;
    $("who").hidden = false;
    $("who-name").textContent = state.me.name + (state.me.approver ? " (approver)" : "");
    $("not-approver").hidden = !!state.me.approver;
    clearInterval(state.timer);
    state.timer = setInterval(refresh, REFRESH_MS);
    refresh();
  }

  function signOut(message) {
    clearInterval(state.timer);
    clearSession();
    Object.assign(state, { credential: null, me: null });
    for (const card of cards.values()) card.remove();
    cards.clear();
    $("workspace").hidden = true;
    $("who").hidden = true;
    $("signin").hidden = false;
    $("credential").value = "";
    const box = $("signin-error");
    box.hidden = !message;
    box.textContent = message || "";
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("signin-form").addEventListener("submit", (event) => {
      event.preventDefault();
      $("signin-error").hidden = true;
      const credential = $("credential").value.trim();
      if (!credential) {
        $("signin-error").textContent = "Paste an API key or ID token first.";
        $("signin-error").hidden = false;
        return;
      }
      signIn($("method-token").checked ? "token" : "key", credential, false);
    });
    $("sign-out").addEventListener("click", () => signOut(""));
    $("tab-pending").addEventListener("click", () => selectTab("pending"));
    $("tab-history").addEventListener("click", () => selectTab("history"));
    const saved = loadSession();
    if (saved && saved.credential) signIn(saved.method, saved.credential, true);
  });
})();
