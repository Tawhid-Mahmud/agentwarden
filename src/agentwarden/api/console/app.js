// AgentWarden approver console.
//
// Everything shown here can contain attacker-controlled text (tool arguments, injected email
// content, evidence snippets). The page therefore never parses data as HTML: every value is placed
// with textContent / DOM nodes, icons are built with createElementNS, and the server sends a CSP
// that forbids inline script and inline style.
"use strict";

(function () {
  const REFRESH_MS = 5000;
  const STORE_KEY = "agentwarden.console";
  const ARM_MS = 6000;
  const narrow = window.matchMedia("(max-width: 860px)");

  const state = {
    method: "key",
    credential: null,
    me: null,
    tab: "pending",
    items: [],
    selected: null, // approval id
    shownKey: null, // id:status of the request currently rendered in the detail pane
    armed: null, // { id, timer } while a high-risk approval waits for confirmation
    busy: false,
    timer: null,
  };
  const notes = new Map(); // approval id -> unsent note text

  const $ = (id) => document.getElementById(id);

  // ------------------------------------------------------------------ DOM helpers
  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = String(value);
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : String(value));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  const ICONS = {
    alert: ["M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z", "M12 9v4", "M12 17h.01"],
    check: ["M22 11.1V12a10 10 0 1 1-5.9-9.1", "M22 4 12 14l-3-3"],
    user: ["M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", "M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z"],
    bot: ["M12 8V4H8", "M5 8h14a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z", "M9 13v2", "M15 13v2"],
    clock: ["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M12 6v6l4 2"],
    back: ["M15 18l-6-6 6-6"],
    keyboard: ["M3 6h18a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1z", "M6 10h.01M10 10h.01M14 10h.01M18 10h.01", "M7 14h10"],
    lock: ["M6 11h12a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1z", "M8 11V7a4 4 0 0 1 8 0v4"],
    file: ["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6"],
    info: ["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M12 16v-4", "M12 8h.01"],
    x: ["M18 6 6 18", "M6 6l12 12"],
  };

  function icon(name) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("class", "icon");
    svg.setAttribute("aria-hidden", "true");
    for (const d of ICONS[name]) {
      const path = document.createElementNS(ns, "path");
      path.setAttribute("d", d);
      svg.append(path);
    }
    return svg;
  }

  function setWidth(node, fraction) {
    node.style.width = Math.round(Math.max(0, Math.min(1, fraction)) * 100) + "%";
  }

  // ------------------------------------------------------------------ session and API
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
    return state.method === "key" ? { "X-API-Key": state.credential } : { Authorization: "Bearer " + state.credential };
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

  // ------------------------------------------------------------------ meaning
  // Plain-language labels for every risk signal the engine emits. Unknown names fall back to the
  // raw name, so a new detector still shows up (and a test makes sure it gets a label).
  const SIGNALS = {
    content_requested_action: "The content asked for this action, the user didn't",
    request_in_user_voice: "Content gives orders as if it were the user",
    instruction_override: "Content tells the AI to ignore its instructions",
    role_hijack: "Content tries to give the AI a new role",
    system_prompt_probe: "Content asks the AI to reveal its instructions",
    agent_addressing: "Content addresses AI agents directly",
    concealment: "Content asks to hide this from the user",
    action_directive: "Content tells the reader to send data somewhere",
    markdown_exfil: "Image link that would leak data in its URL",
    hidden_html: "Text hidden from people with HTML or CSS",
    unicode_tag_smuggling: "Invisible Unicode characters carry hidden text",
    bidi_control_characters: "Text-direction tricks that disguise content",
    zero_width_obfuscation: "Invisible characters split words to dodge filters",
    encoded_instructions: "Encoded (base64) instructions",
    injection_in_arguments: "Injected instructions copied into the arguments",
    llm_injection_verdict: "AI judge flagged the content as an injection",
    tainted_external_destination: "Destination came from content the agent read, not the user",
    tainted_internal_destination: "Internal destination came from content the agent read",
    tainted_path: "File path came from content the agent read",
    secret_in_arguments: "Arguments contain what looks like a credential",
    external_recipient: "Recipient is outside the organization",
    bulk_recipients: "Many recipients at once",
    external_destination: "Data goes to an outside host",
    data_in_url: "Data packed into a URL",
    encoded_payload: "Encoded data in the arguments",
    large_payload: "Unusually large amount of data",
    high_velocity: "Unusually many requests from this agent",
    repeated_denials: "This agent was denied several times recently",
    novel_sensitive_tool: "First time this agent uses this tool",
    detector_error: "A risk check failed (treated as risky)",
  };
  const INJECTION = new Set([
    "instruction_override", "role_hijack", "system_prompt_probe", "agent_addressing", "concealment",
    "markdown_exfil", "hidden_html", "unicode_tag_smuggling", "bidi_control_characters",
    "zero_width_obfuscation", "encoded_instructions", "injection_in_arguments", "llm_injection_verdict",
  ]);
  const RISK_ORDER = { critical: 3, high: 2, medium: 1, low: 0, none: 0 };

  // The answer to "why is this here?", from the most telling signal.
  function verdict(signals) {
    const has = (name) => signals.some((s) => s.name === name);
    if (has("content_requested_action"))
      return { alarm: true, short: "Content asked for this", title: "The request came from the content, not the user",
        text: "Something the agent read asked for this action. The user's own request doesn't mention it." };
    if (has("tainted_external_destination"))
      return { alarm: true, short: "Destination came from content", title: "The destination came from what the agent read",
        text: "The user didn't name this recipient or address. It appears only in content the agent read." };
    if (has("secret_in_arguments"))
      return { alarm: true, short: "Credential in the arguments", title: "A credential may be leaving",
        text: "The arguments contain something that looks like a key, token or password." };
    if (signals.some((s) => INJECTION.has(s.name)))
      return { alarm: true, short: "Injected instructions", title: "The agent read instructions aimed at it",
        text: "Content the agent read contains text written to steer an AI, so its next actions may not be the user's." };
    if (has("request_in_user_voice"))
      return { alarm: true, short: "Orders in the user's voice", title: "Content gives orders as if it were the user",
        text: "Text the agent read is written as the user's own instruction, which is how injected requests often look." };
    return { alarm: false, short: "Routine check", title: "Routine check",
      text: "Nothing suspicious was detected. Policy asks a person to confirm this kind of action." };
  }

  // The strongest piece of evidence that came from content the agent read, if any.
  function contentEvidence(signals) {
    const fromContent = signals
      .filter((s) => (s.location || "").startsWith("context:") && s.evidence)
      .sort((a, b) => b.weight - a.weight);
    if (!fromContent.length) return null;
    const top = fromContent[0];
    const quoted = /: '(.*)'$/.exec(top.evidence); // provenance evidence ends with the quoted request
    if (!quoted) return null;
    return { text: quoted[1], source: top.location.slice("context:".length) };
  }

  function riskLevel(approval) {
    const details = approval.details || {};
    if (details.risk_level) return details.risk_level;
    const score = approval.risk_score;
    return score >= 0.85 ? "critical" : score >= 0.6 ? "high" : score >= 0.3 ? "medium" : "low";
  }

  function urgency(a, b) {
    const level = (x) => RISK_ORDER[riskLevel(x)] || 0;
    return level(b) - level(a) || b.risk_score - a.risk_score || new Date(a.expires_at) - new Date(b.expires_at);
  }

  function actionTitle(tool) {
    const words = String(tool).split(/[_.\-]+/).filter(Boolean);
    const phrase = words.join(" ");
    return phrase.charAt(0).toUpperCase() + phrase.slice(1);
  }

  const FIELD_ORDER = ["to", "cc", "bcc", "recipients", "recipient", "email", "subject", "url", "method", "path",
    "amount", "currency", "account", "channel", "repo", "command", "body", "content", "message", "text"];
  const TARGET_KEYS = ["to", "recipients", "recipient", "email", "url", "path", "channel", "account", "repo"];

  function show(value) {
    if (Array.isArray(value)) return value.map(show).join(", ");
    if (value && typeof value === "object") return JSON.stringify(value);
    return String(value);
  }

  function target(args) {
    for (const key of TARGET_KEYS) {
      if (args && args[key] !== undefined && args[key] !== "") return (key === "to" ? "to " : "") + show(args[key]);
    }
    return null;
  }

  function fields(args) {
    const keys = Object.keys(args || {});
    keys.sort((a, b) => {
      const ia = FIELD_ORDER.indexOf(a), ib = FIELD_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });
    return keys.slice(0, 8).map((key) => [key, show(args[key])]);
  }

  // Which piece of content a value appears in, according to the risk evidence. Only distinctive
  // values count, and never ones the user wrote themselves.
  function valueSource(value, signals, userPrompt) {
    const needle = String(value).toLowerCase();
    if (needle.length < 6 || String(userPrompt || "").toLowerCase().includes(needle)) return null;
    for (const s of signals) {
      if ((s.location || "").startsWith("context:") && (s.evidence || "").toLowerCase().includes(needle)) {
        return s.location.slice("context:".length);
      }
    }
    return null;
  }

  function policyRules(reasons) {
    return (reasons || []).map((reason) => {
      const m = /rule '([^']+)'(?::\s*(.*))?$/.exec(reason);
      return m ? { id: m[1], text: m[2] || "" } : { id: null, text: reason };
    });
  }

  // ------------------------------------------------------------------ time
  function remaining(iso) {
    return Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  }
  function timeLeft(iso) {
    const s = remaining(iso);
    if (s <= 0) return "Expired";
    if (s < 60) return s + "s left";
    if (s < 3600) return Math.ceil(s / 60) + " min left";
    return Math.round(s / 3600) + " h left";
  }
  function ago(iso) {
    const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 45) return "just now";
    if (s < 3600) return Math.round(s / 60) + " min ago";
    if (s < 86400) return Math.round(s / 3600) + " h ago";
    return new Date(iso).toLocaleDateString();
  }
  function clock(iso) {
    return new Date(iso).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  }
  function lifeFraction(a) {
    const total = new Date(a.expires_at) - new Date(a.created_at);
    return total > 0 ? remaining(a.expires_at) * 1000 / total : 0;
  }

  // ------------------------------------------------------------------ toast
  function toast(message, kind) {
    const node = $("toast");
    node.textContent = "";
    node.append(icon(kind === "error" ? "alert" : "check"), el("span", { text: message }));
    node.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { node.hidden = true; }, 4500);
  }

  // ------------------------------------------------------------------ queue
  function visibleItems() {
    if (state.tab === "pending") return state.items.filter((a) => a.status === "pending").sort(urgency);
    return state.items
      .filter((a) => a.status !== "pending")
      .sort((a, b) => new Date(b.reviewed_at || b.expires_at) - new Date(a.reviewed_at || a.expires_at))
      .slice(0, 50);
  }

  function renderQueue() {
    const list = $("queue");
    const items = visibleItems();
    const pending = state.items.filter((a) => a.status === "pending").length;
    $("pending-count").textContent = String(pending);
    $("pending-count").classList.toggle("has", pending > 0);
    document.title = (pending ? "(" + pending + ") " : "") + "AgentWarden Approvals";

    list.textContent = "";
    for (const a of items) {
      const level = riskLevel(a);
      const v = verdict((a.details && a.details.signals) || []);
      const where = target(a.args_preview);
      const selected = a.id === state.selected;
      const meta = a.status === "pending"
        ? [el("span", { class: "pill " + level, text: level }), el("span", { class: "item-time" + (remaining(a.expires_at) < 120 ? " soon" : ""), "data-expires": a.expires_at, text: timeLeft(a.expires_at) })]
        : [el("span", { class: "pill " + a.status, text: a.status === "consumed" ? "used" : a.status }), el("span", { class: "item-time", text: ago(a.reviewed_at || a.expires_at) })];
      const item = el(
        "li",
        { class: "item " + level, role: "option", "aria-selected": String(selected), tabindex: selected ? "0" : "-1", "data-id": a.id,
          onclick: () => select(a.id, true) },
        el("span", { class: "sev", "aria-hidden": "true" }),
        el("div", { class: "item-title", text: actionTitle(a.tool) }),
        el("div", { class: "item-target", text: (where || a.tool) + " · " + a.user_id }),
        el("div", { class: "item-flag" + (v.alarm ? " alarm" : "") }, v.alarm ? icon("alert") : null, el("span", { text: v.short })),
        el("div", { class: "item-meta" }, meta),
      );
      list.append(item);
    }
    const empty = items.length === 0;
    $("queue-empty").hidden = !empty;
    if (empty) {
      $("empty-icon").textContent = "";
      $("empty-icon").append(icon(state.tab === "pending" ? "check" : "clock"));
      $("empty-title").textContent = state.tab === "pending" ? "All clear" : "No decisions yet";
      $("empty-text").textContent = state.tab === "pending"
        ? "Nothing is waiting for a decision. New requests appear here within a few seconds."
        : "Requests you and other approvers decide will be listed here.";
    }
  }

  // ------------------------------------------------------------------ detail
  function renderDetail(force) {
    const a = state.items.find((x) => x.id === state.selected);
    const key = a ? a.id + ":" + a.status : null;
    if (!force && key === state.shownKey) { tick(); return; }
    state.shownKey = key;
    disarm();
    const body = $("detail-body");
    body.textContent = "";
    $("detail-empty").hidden = !!a;
    body.hidden = !a;
    if (!a) return;

    const details = a.details || {};
    const signals = details.signals || [];
    const level = riskLevel(a);
    const v = verdict(signals);
    const quote = contentEvidence(signals);
    const chain = (details.actor_chain && details.actor_chain.length ? details.actor_chain : [a.agent_id]).join(" → ");

    const sheet = el("div", { class: "sheet" });
    sheet.append(el("button", { type: "button", class: "text-button back", onclick: closeDetail }, icon("back"), "All requests"));

    // Header: what, for whom, how risky, how long it can wait.
    const head = el(
      "header",
      { class: "d-head" },
      el(
        "div",
        { class: "d-head-top" },
        el("h1", { class: "d-title", id: "detail-title" }, actionTitle(a.tool), el("code", { text: a.tool })),
        el("div", { class: "d-pills" },
          el("span", { class: "pill " + level }, el("span", { class: "dot" }), level + " risk · " + Number(a.risk_score).toFixed(2)),
          a.status !== "pending" ? el("span", { class: "pill " + a.status, text: a.status === "consumed" ? "used" : a.status }) : null),
      ),
      el("div", { class: "d-sub" },
        el("span", {}, "Agent ", el("b", { text: chain })),
        el("span", {}, "for ", el("b", { text: a.user_id })),
        el("span", { text: "Requested " + ago(a.created_at) })),
    );
    if (a.status === "pending") {
      const bar = el("span");
      setWidth(bar, lifeFraction(a));
      head.append(el("div", { class: "timer" },
        el("div", { class: "timer-bar", "aria-hidden": "true" }, bar),
        el("span", { class: "timer-text", "data-expires": a.expires_at, text: timeLeft(a.expires_at) + " · the agent is waiting until " + clock(a.expires_at) })));
      bar.setAttribute("data-life", a.id);
    }
    sheet.append(head);

    if (a.status !== "pending") sheet.append(outcome(a));

    // Verdict, with the request the content made, quoted.
    sheet.append(el(
      "section",
      { class: "verdict" + (v.alarm ? " alarm" : ""), "aria-label": "Assessment" },
      el("span", { class: "v-icon" }, icon(v.alarm ? "alert" : "check")),
      el("h2", { text: v.title }),
      el("p", { class: "v-text", text: v.text }),
      quote ? el("blockquote", { class: "quote" },
        el("span", { class: "quote-src", text: "Found in " + quote.source }),
        el("p", { text: quote.text })) : null,
    ));

    // The core comparison: what the person asked for vs. what the agent wants to do.
    const asked = el("section", { class: "panel", "aria-label": "What the user asked" },
      el("span", { class: "panel-title" }, icon("user"), a.user_id + " asked"),
      el("p", { class: "said" + (details.user_prompt ? "" : " missing"), text: details.user_prompt || "The agent didn't report the user's request." }),
      details.task ? el("p", { class: "task", text: "Task: " + details.task }) : null);
    const list = el("dl", { class: "fields" });
    for (const [name, value] of fields(a.args_preview)) {
      const source = valueSource(value, signals, details.user_prompt);
      const long = value.length > 120;
      list.append(
        el("dt", { text: name }),
        el("dd", {},
          el("span", { class: "value" + (source ? " flagged" : "") + (long ? " long" : ""), text: long ? value.slice(0, 280) + (value.length > 280 ? "…" : "") : value }),
          source ? el("span", { class: "flag-note" }, icon("alert"), "From " + source + ", not from the user") : null),
      );
    }
    const wants = el("section", { class: "panel", "aria-label": "What the agent wants to do" },
      el("span", { class: "panel-title" }, icon("bot"), "The agent wants to"),
      list.childElementCount ? list : el("p", { class: "said missing", text: "Run " + a.tool + " with no arguments." }));
    sheet.append(el("div", { class: "compare" }, asked, wants));

    // Evidence, strongest first, in plain words.
    const rows = signals.slice().sort((x, y) => y.weight - x.weight).map((s) => {
      const meter = el("span");
      setWidth(meter, s.weight);
      return el("div", { class: "signal" },
        el("span", { class: "signal-label", text: SIGNALS[s.name] || s.name }),
        el("div", { class: "signal-meter" },
          el("div", { class: "meter " + (s.weight >= 0.5 ? "hi" : s.weight >= 0.25 ? "mid" : ""), "aria-hidden": "true" }, meter),
          el("span", { class: "signal-weight", text: Number(s.weight).toFixed(2) })),
        s.evidence ? el("span", { class: "signal-evidence", text: s.evidence + (s.location ? " · " + s.location.replace("context:", "in ") : "") }) : null,
        el("span", { class: "signal-tech", text: s.detector + " / " + s.name }));
    });
    sheet.append(el("section", { "aria-labelledby": "evidence-title" },
      el("h2", { class: "section-title", id: "evidence-title", text: "Risk evidence" }),
      el("div", { class: "signals" }, rows.length ? rows : el("p", { class: "no-signals", text: "No risk signals." }))));

    const rules = policyRules(a.reasons);
    if (rules.length) {
      sheet.append(el("section", { "aria-labelledby": "policy-title" },
        el("h2", { class: "section-title", id: "policy-title", text: "Why policy asks a person" }),
        el("div", { class: "rules" }, rules.map((r) => el("div", { class: "rule" },
          r.id ? el("code", { text: r.id }) : el("span"),
          el("p", { text: r.text || "Required by policy." }))))));
    }

    // Everything else, for the curious and for incident response.
    const ids = el("dl", { class: "ids" });
    for (const [label, value] of [["Decision", a.decision_id], ["Approval", a.id], ["Call hash", a.call_hash]]) {
      ids.append(el("dt", { text: label }), el("dd", {}, el("code", { text: value }), copyButton(value, label)));
    }
    sheet.append(el("details", { class: "more" },
      el("summary", { text: "Raw arguments, sources and IDs" }),
      el("div", { class: "more-body" },
        el("div", {}, el("h3", { class: "section-title", text: "Arguments (secrets redacted)" }), el("pre", { class: "raw", text: JSON.stringify(a.args_preview, null, 2) })),
        el("div", {}, el("h3", { class: "section-title", text: "Content the agent had read" }),
          (details.context_sources || []).length
            ? el("div", { class: "chips" }, details.context_sources.map((s) => el("span", { class: "chip", text: s })))
            : el("p", { class: "hint", text: "None reported." })),
        el("div", {}, el("h3", { class: "section-title", text: "For the audit log and SIEM" }), ids))));

    body.append(sheet);
    if (a.status === "pending") body.append(decisionBar(a, level));
  }

  function copyButton(value, label) {
    return el("button", { type: "button", class: "text-button", "aria-label": "Copy " + label + " ID",
      onclick: async () => {
        try { await navigator.clipboard.writeText(value); toast(label + " ID copied"); }
        catch (_) { toast("Couldn't copy. Select the text instead.", "error"); }
      } }, "Copy");
  }

  function outcome(a) {
    const word = { approved: "Approved", denied: "Denied", consumed: "Approved and used", expired: "Expired without a decision" }[a.status] || a.status;
    const who = a.reviewer ? " by " + a.reviewer : "";
    const when = a.reviewed_at ? " at " + clock(a.reviewed_at) : "";
    return el("section", { class: "outcome " + a.status },
      icon(a.status === "denied" || a.status === "expired" ? "x" : "check"),
      el("div", {}, el("strong", { text: word + who + when }),
        a.note ? el("p", { text: "“" + a.note + "”" }) : el("p", { text: a.status === "consumed" ? "The agent ran the approved call." : "No note." })));
  }

  function decisionBar(a, level) {
    const own = state.me && a.user_id === state.me.id;
    const inner = el("div", { class: "decide-inner" });
    const bar = el("div", { class: "decide", role: "region", "aria-label": "Decision" }, inner);
    if (own || !state.me || !state.me.approver) {
      inner.append(el("p", { class: "locked" }, icon("lock"),
        own ? "This request was made on your behalf, so another approver has to review it." : "You need the approver role to decide."));
      return bar;
    }
    const note = el("input", { type: "text", class: "note", id: "note", placeholder: "Add a note (optional)", maxlength: "1000", "aria-label": "Note for the audit log" });
    note.value = notes.get(a.id) || "";
    note.addEventListener("input", () => notes.set(a.id, note.value));
    const deny = el("button", { type: "button", class: "button deny", id: "deny", onclick: () => decide(a, "deny") }, "Deny", el("kbd", { text: "D" }));
    const approve = el("button", { type: "button", class: "button approve", id: "approve", onclick: () => decide(a, "approve") }, "Approve", el("kbd", { text: "A" }));
    const consequence = el("p", { class: "consequence", id: "consequence" });
    setConsequence(consequence, a, false);
    inner.append(note, deny, approve, consequence);
    bar.setAttribute("data-level", level);
    return bar;
  }

  function setConsequence(node, a, warn) {
    node.textContent = "";
    node.classList.toggle("warn", warn);
    node.append(icon(warn ? "alert" : "info"), warn
      ? "High risk. Read the evidence, then press Approve again to confirm. Esc cancels."
      : "Approving lets the agent run this exact call once, until " + clock(a.expires_at) + ". Denying refuses it.");
  }

  function disarm() {
    if (!state.armed) return;
    clearTimeout(state.armed.timer);
    state.armed = null;
    const approve = $("approve");
    if (approve) {
      approve.classList.remove("armed");
      approve.firstChild.textContent = "Approve";
      const a = state.items.find((x) => x.id === state.selected);
      if (a && $("consequence")) setConsequence($("consequence"), a, false);
    }
  }

  async function decide(a, verb) {
    if (state.busy || !$("approve")) return;
    const level = riskLevel(a);
    if (verb === "approve" && (level === "high" || level === "critical") && !(state.armed && state.armed.id === a.id)) {
      // Approving a hijacked call is the costliest mistake an approver can make: ask twice.
      state.armed = { id: a.id, timer: setTimeout(disarm, ARM_MS) };
      $("approve").classList.add("armed");
      $("approve").firstChild.textContent = "Confirm approval";
      setConsequence($("consequence"), a, true);
      $("approve").focus();
      return;
    }
    disarm();
    state.busy = true;
    $("approve").disabled = $("deny").disabled = true;
    const note = notes.get(a.id) || "";
    try {
      await api("/v1/approvals/" + encodeURIComponent(a.id) + "/" + verb, { method: "POST", body: { note } });
      notes.delete(a.id);
      toast(verb === "approve" ? "Approved. The agent can run this exact call once." : "Denied. The agent's call will be refused.");
      const order = visibleItems().map((x) => x.id);
      const next = order[order.indexOf(a.id) + 1] || order[order.indexOf(a.id) - 1] || null;
      a.status = verb === "approve" ? "approved" : "denied";
      state.selected = narrow.matches ? null : next;
      if (narrow.matches) closeDetail();
      renderQueue();
      renderDetail(true);
      refresh();
    } catch (error) {
      toast(error.message, "error");
      if ($("approve")) $("approve").disabled = $("deny").disabled = false;
    } finally {
      state.busy = false;
    }
  }

  // ------------------------------------------------------------------ selection
  function select(id, userAction) {
    if (id !== state.selected) disarm();
    state.selected = id;
    for (const node of $("queue").children) {
      const on = node.getAttribute("data-id") === id;
      node.setAttribute("aria-selected", String(on));
      node.tabIndex = on ? 0 : -1;
      if (on && userAction) node.scrollIntoView({ block: "nearest" });
    }
    if (userAction && narrow.matches) $("workspace").classList.add("reading");
    renderDetail(false);
    if (userAction) $("detail").scrollTop = 0;
  }

  function move(step) {
    const ids = visibleItems().map((a) => a.id);
    if (!ids.length) return;
    const at = ids.indexOf(state.selected);
    const next = ids[Math.max(0, Math.min(ids.length - 1, at < 0 ? 0 : at + step))];
    select(next, true);
    const node = $("queue").querySelector('[data-id="' + CSS.escape(next) + '"]');
    if (node && !narrow.matches) node.focus();
  }

  function closeDetail() {
    $("workspace").classList.remove("reading");
    const node = $("queue").querySelector('[aria-selected="true"]');
    if (node) node.focus();
  }

  // ------------------------------------------------------------------ refresh loop
  function tick() {
    for (const node of document.querySelectorAll("[data-expires]")) {
      const left = timeLeft(node.getAttribute("data-expires"));
      node.textContent = node.classList.contains("timer-text")
        ? left + " · the agent is waiting until " + clock(node.getAttribute("data-expires"))
        : left;
      if (node.classList.contains("item-time")) node.classList.toggle("soon", remaining(node.getAttribute("data-expires")) < 120);
    }
    const a = state.items.find((x) => x.id === state.selected);
    const bar = document.querySelector("[data-life]");
    if (a && bar) setWidth(bar, lifeFraction(a));
  }

  async function refresh() {
    if (!state.me || !state.me.approver) return;
    const sync = $("sync");
    try {
      const all = await api("/v1/approvals?limit=200");
      const before = state.items.find((x) => x.id === state.selected);
      state.items = all;
      const after = all.find((x) => x.id === state.selected);
      if (before && before.status === "pending" && after && after.status !== "pending" && !state.busy) {
        toast("This request was just " + (after.status === "consumed" ? "used" : after.status) + (after.reviewer ? " by " + after.reviewer : "") + ".");
      }
      const visible = visibleItems();
      if (!state.selected || !visible.some((x) => x.id === state.selected)) {
        if (!after || state.tab === "pending") state.selected = narrow.matches ? null : (visible[0] && visible[0].id) || null;
      }
      renderQueue();
      renderDetail(false);
      sync.classList.remove("stale");
      sync.textContent = "Live";
      sync.title = "Updated " + new Date().toLocaleTimeString();
    } catch (error) {
      if (error.status === 401) { signOut("Your session expired. Sign in again."); return; }
      sync.classList.add("stale");
      sync.textContent = "Reconnecting…";
      sync.title = error.message;
    }
  }

  function selectTab(tab) {
    state.tab = tab;
    $("tab-pending").setAttribute("aria-selected", String(tab === "pending"));
    $("tab-history").setAttribute("aria-selected", String(tab === "history"));
    const visible = visibleItems();
    state.selected = narrow.matches ? null : (visible[0] && visible[0].id) || null;
    closeDetail();
    renderQueue();
    renderDetail(true);
  }

  // ------------------------------------------------------------------ sign-in
  function initials(name) {
    return String(name || "?").split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join("");
  }

  async function signIn(method, credential, quiet) {
    state.method = method;
    state.credential = credential;
    const button = $("signin-button");
    button.disabled = true;
    try {
      state.me = await api("/v1/me");
    } catch (error) {
      state.credential = null;
      clearSession();
      button.disabled = false;
      if (!quiet) {
        const box = $("signin-error");
        box.textContent = error.status === 401 ? "That credential wasn't accepted. Check it and try again." : error.message;
        box.hidden = false;
        $("credential").focus();
      }
      return;
    }
    button.disabled = false;
    saveSession();
    $("signin").hidden = true;
    $("workspace").hidden = false;
    $("account").hidden = false;
    $("avatar").textContent = initials(state.me.name);
    $("account-name").textContent = state.me.name;
    $("account-role").textContent = state.me.approver ? "Approver" : "No approver role";
    $("not-approver").hidden = !!state.me.approver;
    clearInterval(state.timer);
    state.timer = setInterval(refresh, REFRESH_MS);
    clearInterval(state.ticker);
    state.ticker = setInterval(tick, 1000);
    await refresh();
  }

  function signOut(message) {
    clearInterval(state.timer);
    clearInterval(state.ticker);
    clearSession();
    Object.assign(state, { credential: null, me: null, items: [], selected: null, shownKey: null });
    notes.clear();
    $("queue").textContent = "";
    $("detail-body").textContent = "";
    $("workspace").hidden = true;
    $("account").hidden = true;
    $("signin").hidden = false;
    $("credential").value = "";
    document.title = "AgentWarden Approvals";
    const box = $("signin-error");
    box.hidden = !message;
    box.textContent = message || "";
  }

  // ------------------------------------------------------------------ keyboard
  function onKey(event) {
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName);
    if (event.key === "Escape") {
      if (state.armed) { disarm(); event.preventDefault(); return; }
      if (typing) { event.target.blur(); return; }
      if ($("workspace").classList.contains("reading")) closeDetail();
      return;
    }
    if (typing || $("workspace").hidden || $("help").open) return;
    const a = state.items.find((x) => x.id === state.selected);
    switch (event.key) {
      case "j": case "ArrowDown": move(1); break;
      case "k": case "ArrowUp": move(-1); break;
      case "a": if (a && a.status === "pending") decide(a, "approve"); break;
      case "d": if (a && a.status === "pending") decide(a, "deny"); break;
      case "n": if ($("note")) $("note").focus(); break;
      case "?": $("help").showModal(); break;
      case "Enter": if (event.target.classList && event.target.classList.contains("item")) select(event.target.getAttribute("data-id"), true); else return; break;
      default: return;
    }
    event.preventDefault();
  }

  // ------------------------------------------------------------------ start
  document.addEventListener("DOMContentLoaded", () => {
    $("help-button").append(icon("keyboard"));
    $("help-button").addEventListener("click", () => $("help").showModal());
    $("help-close").addEventListener("click", () => $("help").close());
    for (const radio of document.querySelectorAll('input[name="method"]')) {
      radio.addEventListener("change", () => {
        $("credential-label").textContent = $("method-token").checked ? "ID token" : "API key";
      });
    }
    $("signin-form").addEventListener("submit", (event) => {
      event.preventDefault();
      $("signin-error").hidden = true;
      const credential = $("credential").value.trim();
      if (!credential) {
        $("signin-error").textContent = "Paste an API key or ID token first.";
        $("signin-error").hidden = false;
        $("credential").focus();
        return;
      }
      signIn($("method-token").checked ? "token" : "key", credential, false);
    });
    $("sign-out").addEventListener("click", () => signOut(""));
    $("tab-pending").addEventListener("click", () => selectTab("pending"));
    $("tab-history").addEventListener("click", () => selectTab("history"));
    document.addEventListener("keydown", onKey);
    narrow.addEventListener("change", () => { if (!narrow.matches) $("workspace").classList.remove("reading"); });
    const saved = loadSession();
    if (saved && saved.credential) signIn(saved.method, saved.credential, true);
    else $("credential").focus();
  });
})();
