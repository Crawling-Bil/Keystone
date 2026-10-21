// Guided firewall conversion (Convert Firewall page).
//
// The server owns the rules: every "Validate & continue" sends the whole
// wizard state, the server regenerates the PAN-OS config, checks it, and
// answers with each step's status. This file only edits the state, draws
// the current step, and moves forward when the server says the step passed.
(function () {
  const form = document.getElementById("converter-form");
  const root = document.getElementById("wizard-result");
  const startButton = document.getElementById("wizard-start-button");
  if (!form || !root || !startButton) return;

  const esc = value => window.NES.escape(value);
  const $ = id => document.getElementById(id);
  const targetVendor = $("target-vendor");
  const otherPanels = ["converter-empty", "converter-result", "mapping-result", "batch-result"];

  const wiz = { token: null, result: null, state: null, current: 0, busy: false, dirty: false };

  function updateStartVisibility() {
    const isPaloAlto = ((targetVendor && targetVendor.value) || "").toLowerCase() === "palo alto";
    startButton.classList.toggle("hidden", !isPaloAlto);
  }
  targetVendor?.addEventListener("change", updateStartVisibility);
  updateStartVisibility();

  // Any other flow on the page hides the wizard.
  ["convert-button", "preview-mapping-button", "batch-convert-button"].forEach(id => {
    $(id)?.addEventListener("click", () => root.classList.add("hidden"));
  });

  function showWizard() {
    otherPanels.forEach(id => $(id)?.classList.add("hidden"));
    root.classList.remove("hidden");
  }

  async function postJson(url, body) {
    const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await response.json().catch(() => ({ ok: false, error: `HTTP ${response.status}` }));
    if (!data.ok) throw new Error(data.error || "Request failed.");
    return data.result;
  }

  startButton.addEventListener("click", async () => {
    const data = new FormData();
    const file = $("config-file")?.files?.[0];
    const text = $("config-text")?.value || "";
    if (file) data.set("config_file", file);
    else if (text.trim()) data.set("config_text", text);
    else { window.NES.toast("Upload or paste the MikroTik export first.", "error"); return; }
    data.set("source_vendor", $("source-vendor")?.value || "Auto Detect");
    data.set("target_vendor", "Palo Alto");
    data.set("target_model", $("target-model")?.value || "");
    window.NES.setLoading(startButton, true, "Reading source...");
    try {
      const response = await fetch("/configuration/api/wizard/start", { method: "POST", body: data });
      const payload = await response.json();
      if (!payload.ok) throw new Error(payload.error || "Could not start.");
      wiz.token = payload.result.token;
      wiz.current = 0;
      accept(payload.result);
      showWizard();
      root.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(startButton, false);
    }
  });

  function accept(result) {
    wiz.result = result;
    wiz.state = JSON.parse(JSON.stringify(result.state));
    wiz.dirty = false;
    $("wizard-hostname-line").textContent =
      `${result.hostname}: ${result.source_vendor} to ${result.target_vendor}. Each step is checked before the next one opens.`;
    render();
  }

  async function validate(advance) {
    if (wiz.busy || !wiz.token) return;
    wiz.busy = true;
    const nextButton = $("wizard-next");
    window.NES.setLoading(nextButton, true, "Checking...");
    try {
      const result = await postJson(`/configuration/api/wizard/${wiz.token}/validate`, { state: wiz.state });
      const step = result.steps[wiz.current];
      wiz.result = result;
      wiz.state = JSON.parse(JSON.stringify(result.state));
      wiz.dirty = false;
      if (advance && step.status === "ok" && wiz.current < result.steps.length - 1) {
        wiz.current += 1;
      } else if (advance && step.status !== "ok") {
        window.NES.toast(step.status === "error" ? "Fix the errors in this step first." : "Read and acknowledge the warnings first.", "error");
      }
      render();
      return true;
    } catch (error) {
      window.NES.toast(error.message, "error");
      return false;
    } finally {
      wiz.busy = false;
      window.NES.setLoading(nextButton, false);
      renderFooter();
    }
  }

  // Leaving a step with unchecked edits checks them first, so the steps,
  // the review and the download always show the state the server checked.
  async function go(index) {
    if (wiz.dirty && !(await validate(false))) return;
    const target = wiz.result.steps[index];
    if (!target) return;
    if (index > wiz.current && !target.reachable) {
      window.NES.toast("Finish the open steps first.", "error");
      return;
    }
    wiz.current = index;
    render();
  }

  function downloadUrl() {
    return `/configuration/api/wizard/${wiz.token}/download?rev=${encodeURIComponent(wiz.result.revision || "")}`;
  }

  $("wizard-next").addEventListener("click", () => validate(true));
  $("wizard-recheck").addEventListener("click", () => validate(false));
  $("wizard-back").addEventListener("click", () => { if (wiz.current > 0) go(wiz.current - 1); });
  $("wizard-restart").addEventListener("click", () => {
    wiz.token = null; wiz.result = null;
    root.classList.add("hidden");
    $("converter-empty")?.classList.remove("hidden");
  });
  $("wizard-ack").addEventListener("change", event => {
    const step = wiz.result.steps[wiz.current];
    const keys = step.issues.filter(i => i.severity === "warning").map(i => i.key);
    const set = new Set(wiz.state.acknowledged || []);
    keys.forEach(k => (event.target.checked ? set.add(k) : set.delete(k)));
    wiz.state.acknowledged = [...set];
    wiz.dirty = true;
    validate(false);
  });

  // ------------------------------------------------------------------ rendering

  function render() {
    renderStepper();
    const step = wiz.result.steps[wiz.current];
    $("wizard-step-index").textContent = `Step ${wiz.current + 1} of ${wiz.result.steps.length}`;
    $("wizard-step-title").textContent = step.label;
    $("wizard-step-summary").textContent = step.summary;
    const status = $("wizard-step-status");
    status.className = `wz-status is-${step.status}`;
    status.textContent = statusText(step);
    $("wizard-editor").innerHTML = (EDITORS[step.key] || readOnlyEditor)(step);
    bindEditor(step.key);
    renderIssues(step);
    renderNotes(step);
    renderLines(step);
    renderFooter();
  }

  function statusText(step) {
    if (step.status === "error") return `${step.counts.error} error${step.counts.error === 1 ? "" : "s"}`;
    if (step.status === "warning") return `${step.counts.pending} warning${step.counts.pending === 1 ? "" : "s"} to read`;
    return step.counts.warning ? "Passed (warnings read)" : "Passed";
  }

  function renderStepper() {
    $("wizard-stepper").innerHTML = wiz.result.steps.map((step, index) => {
      const classes = ["wz-dot", `is-${step.status}`];
      if (index === wiz.current) classes.push("is-current");
      if (!step.reachable) classes.push("is-locked");
      return `<li><button type="button" class="${classes.join(" ")}" data-step="${index}" ${step.reachable ? "" : "disabled"}
        aria-current="${index === wiz.current ? "step" : "false"}" title="${esc(step.summary)}">
        <span class="wz-dot-n">${index + 1}</span><span class="wz-dot-label">${esc(step.label)}</span></button></li>`;
    }).join("");
    $("wizard-stepper").querySelectorAll("button[data-step]").forEach(button => {
      button.addEventListener("click", () => go(Number(button.dataset.step)));
    });
  }

  function renderIssues(step) {
    const box = $("wizard-issues");
    if (!step.issues.length) {
      box.innerHTML = `<p class="wz-clean">No problems found in this step.</p>`;
      return;
    }
    box.innerHTML = step.issues.map(issue => `
      <article class="wz-issue is-${issue.severity}${issue.acknowledged ? " is-ack" : ""}">
        <span class="wz-pill">${esc(issue.severity)}</span>
        <div><p class="wz-msg">${esc(issue.message)}</p>${issue.fix ? `<p class="wz-fix">${esc(issue.fix)}</p>` : ""}</div>
        <code class="wz-code">${esc(issue.code)}${issue.line ? ` · line ${issue.line}` : ""}</code>
      </article>`).join("");
  }

  function renderNotes(step) {
    $("wizard-notes-count").textContent = step.notes.length ? `(${step.notes.length})` : "";
    $("wizard-notes-fold").classList.toggle("hidden", !step.notes.length);
    $("wizard-notes").innerHTML = step.notes.map(note => `<li>${esc(note)}</li>`).join("");
  }

  function renderLines(step) {
    const fold = $("wizard-lines-fold");
    if (step.key === "review") { fold.classList.add("hidden"); return; }
    fold.classList.toggle("hidden", !step.lines.length);
    $("wizard-lines-count").textContent = step.lines.length ? `(${step.lines.length})` : "";
    $("wizard-lines").textContent = step.lines.map(l => `${String(l.n).padStart(4, " ")}  ${l.text}`).join("\n");
  }

  function renderFooter() {
    if (!wiz.result) return;
    const step = wiz.result.steps[wiz.current];
    const last = wiz.current === wiz.result.steps.length - 1;
    $("wizard-back").disabled = wiz.current === 0;
    $("wizard-next").classList.toggle("hidden", last);
    const warnings = step.issues.filter(i => i.severity === "warning");
    const ackWrap = $("wizard-ack-wrap");
    ackWrap.classList.toggle("hidden", !warnings.length);
    $("wizard-ack").checked = warnings.length > 0 && warnings.every(i => i.acknowledged);
    $("wizard-ack-label").textContent = `I have read the ${warnings.length} warning${warnings.length === 1 ? "" : "s"} in this step`;
  }

  // ------------------------------------------------------------------ editors

  const SDWAN_TYPES = ["none", "ethernet", "adsl", "cablemodem", "fiber", "lte", "mpls", "satellite", "private1", "public1"];

  function portControl(name, value) {
    const ports = wiz.result.options.target_ports;
    if (ports.length) {
      const known = !value || ports.includes(value);
      return `<select data-bind="${bind('interfaces', name, 'pan_interface')}" aria-label="Target port for ${esc(name)}">
        <option value="">Not mapped (skip)</option>
        ${ports.map(p => `<option ${p === value ? "selected" : ""}>${esc(p)}</option>`).join("")}
        ${known ? "" : `<option selected>${esc(value)}</option>`}
      </select>`;
    }
    return `<input type="text" data-bind="${bind('interfaces', name, 'pan_interface')}" value="${esc(value)}" placeholder="ethernet1/N" aria-label="Target port for ${esc(name)}">`;
  }

  function statusBadge(fact) {
    return fact.disabled
      ? `<span class="wz-state is-off" title="Disabled in the source; written with link-state down">Disabled</span>`
      : `<span class="wz-state">Enabled</span>`;
  }

  function memberPorts(bridgeName) {
    const bridge = wiz.result.facts[bridgeName] || {};
    return (bridge.bridge_ports || []).map(p => (wiz.state.interfaces[p] || {}).pan_interface).filter(Boolean);
  }

  function logicalTarget(name) {
    const row = wiz.state.interfaces[name] || {}, f = wiz.result.facts[name] || {};
    if (f.type === "bridge") {
      if (row.mode === "routed") return memberPorts(name)[0] || "?";
      return row.unit ? `vlan.${row.unit}` : "vlan.(auto)";
    }
    const tag = row.tag || f.vlan_id || "?";
    if (row.mode === "vlan") return `vlan.${row.unit || tag}`;
    let parent = row.parent_port;
    if (!parent) parent = f.parent_is_bridge ? (memberPorts(f.parent).length === 1 ? memberPorts(f.parent)[0] : "") : (wiz.state.interfaces[f.parent] || {}).pan_interface;
    return `${parent || "?"}.${tag}`;
  }

  function logicalRow(name, row, f) {
    const isBridge = f.type === "bridge";
    const modes = isBridge
      ? [["vlan", "vlan.N"], ["routed", "Routed on port"]]
      : (f.parent_is_bridge ? [["vlan", "vlan.N + tagged L2"], ["subinterface", "L3 sub-interface"]] : [["subinterface", "L3 sub-interface"]]);
    const modeCell = `<select data-bind="${bind("interfaces", name, "mode")}" data-rerender="1" aria-label="PAN-OS shape for ${esc(name)}">
      ${modes.map(([v, label]) => `<option value="${v}" ${v === row.mode ? "selected" : ""}>${label}</option>`).join("")}</select>`;
    const ports = Object.values(wiz.state.interfaces).map(r => r.pan_interface).filter(Boolean);
    const parentCell = !isBridge && row.mode === "subinterface"
      ? `<select data-bind="${bind("interfaces", name, "parent_port")}" data-rerender="1" aria-label="Parent port for ${esc(name)}">
          <option value="">Auto</option>${[...new Set(ports)].map(p => `<option ${p === row.parent_port ? "selected" : ""}>${esc(p)}</option>`).join("")}</select>`
      : `<span class="wz-muted">-</span>`;
    const tagCell = isBridge ? `<span class="wz-muted">untagged</span>`
      : `<input type="number" min="1" max="4094" data-bind="${bind("interfaces", name, "tag")}" data-rerender="1" value="${esc(row.tag)}" aria-label="VLAN tag for ${esc(name)}">`;
    const unitCell = row.mode === "subinterface" || row.mode === "routed" ? `<span class="wz-muted">-</span>`
      : `<input type="number" min="1" max="9999" data-bind="${bind("interfaces", name, "unit")}" data-rerender="1" value="${esc(row.unit)}" placeholder="auto" aria-label="vlan.N unit for ${esc(name)}">`;
    const on = isBridge ? (f.bridge_ports || []).join(", ") || "-" : `${f.parent}${f.parent_is_bridge ? " (bridge)" : ""}`;
    return `<tr class="${f.used ? "" : "is-unused"}">
      <td><strong>${esc(name)}</strong><small>${isBridge ? `bridge: ${esc(on)}` : `VLAN ${esc(f.vlan_id ?? "")} on ${esc(on)}`}</small><small>${esc((f.addresses || []).join(", ") || "no address")}</small>${f.comment ? `<small>${esc(f.comment)}</small>` : ""}</td>
      <td>${statusBadge(f)}</td>
      <td>${modeCell}</td>
      <td><code class="wz-result">${esc(logicalTarget(name))}</code></td>
      <td>${parentCell}</td><td>${tagCell}</td><td>${unitCell}</td></tr>`;
  }

  function roleBadge(fact) {
    if (!fact || !fact.role) return `<span class="wz-role">-</span>`;
    return `<span class="wz-role is-${esc(fact.role)}" title="${esc(fact.role_reason)}">${esc(fact.role_label)}</span>`;
  }

  const EDITORS = {
    target(step) {
      const s = wiz.state, models = wiz.result.options.models;
      return `<div class="wz-form">
        <label class="cv-field"><span>Target model</span>
          <select data-bind="${bind('target_model')}"><option value="">Not sure (ports are not checked)</option>
          ${models.map(m => `<option value="${esc(m.model)}" ${m.model === s.target_model ? "selected" : ""}>${esc(m.label)}</option>`).join("")}</select></label>
        <label class="wz-check"><input type="checkbox" data-bind="${bind('deployment', 'panorama')}" ${s.deployment.panorama ? "checked" : ""}> Generate for Panorama (template + device group)</label>
        <div class="cv-row ${s.deployment.panorama ? "" : "hidden"}" id="wz-panorama-names">
          <label class="cv-field"><span>Template</span><input type="text" data-bind="${bind('deployment', 'template_name')}" value="${esc(s.deployment.template_name)}"></label>
          <label class="cv-field"><span>Device group</span><input type="text" data-bind="${bind('deployment', 'device_group_name')}" value="${esc(s.deployment.device_group_name)}"></label>
        </div>
        <p class="wz-hint">Port counts come from the vendor data sheet. Confirm the numbering once per model with <code>show interface hardware</code> on a real unit.</p>
      </div>`;
    },
    interfaces() {
      const facts = wiz.result.facts;
      const rows = Object.entries(wiz.state.interfaces).filter(([name]) => (facts[name] || {}).physical !== false);
      const logical = Object.entries(wiz.state.interfaces).filter(([name]) => ["vlan", "bridge"].includes((facts[name] || {}).type));
      return `<p class="wz-hint">Pick the target port for each source port. To swap LAN and INET, give each one the other's port; zones, NAT, routes, VPN and MSS follow automatically.</p>
      <div class="table-wrap wz-table"><table>
        <thead><tr><th>Source</th><th>Status</th><th>Role</th><th>Addresses</th><th>Bridge</th><th>Target port</th></tr></thead>
        <tbody>${rows.map(([name, row]) => {
          const f = facts[name] || {};
          return `<tr class="${f.used ? "" : "is-unused"}">
            <td><strong>${esc(name)}</strong>${f.default_name && f.default_name !== name ? `<small>${esc(f.default_name)}</small>` : ""}${f.comment ? `<small>${esc(f.comment)}</small>` : ""}${f.used || f.bridge ? "" : `<small>no IP, bridge or rule uses it: leave unmapped to skip</small>`}</td>
            <td>${statusBadge(f)}</td>
            <td>${roleBadge(f)}</td>
            <td>${esc((f.addresses || []).join(", ") || (f.dhcp_client ? "DHCP client" : "-"))}</td>
            <td>${esc(f.bridge || "-")}</td>
            <td>${portControl(name, row.pan_interface)}</td></tr>`;
        }).join("")}</tbody></table></div>
      ${logical.length ? `<h4 class="wz-sub">VLAN and bridge interfaces</h4>
      <p class="wz-hint"><strong>VLAN interface</strong>: vlan.N, with a tagged layer2 sub-interface on every bridge port (the switch side keeps its trunk).
        <strong>Sub-interface</strong>: layer3 port.tag on one port (router-on-a-stick). A bridge with one port can be <strong>routed</strong> on that port instead of vlan.N.</p>
      <div class="table-wrap wz-table"><table>
        <thead><tr><th>Source</th><th>Status</th><th>PAN-OS as</th><th>Result</th><th>Parent port</th><th>Tag</th><th>vlan.N unit</th></tr></thead>
        <tbody>${logical.map(([name, row]) => logicalRow(name, row, facts[name] || {})).join("")}</tbody></table></div>` : ""}`;
    },
    zones() {
      const facts = wiz.result.facts;
      const rows = Object.entries(wiz.state.interfaces);
      return `<p class="wz-hint">One zone per interface. A bridge member port is layer2 and takes the bridge's zone. Rules written on a RouterOS interface list use the zones of the list's members.</p>
      <div class="table-wrap wz-table"><table>
        <thead><tr><th>Interface</th><th>Role</th><th>Target</th><th>Zone</th><th>SD-WAN link</th></tr></thead>
        <tbody>${rows.map(([name, row]) => {
          const f = facts[name] || {};
          const zoneCell = f.physical !== false && !row.pan_interface
            ? `<span class="wz-muted">not mapped, not converted</span>`
            : f.bridge
            ? `<span class="wz-muted">follows ${esc(f.bridge)}</span>`
            : `<input type="text" data-bind="${bind('interfaces', name, 'zone')}" value="${esc(row.zone)}" aria-label="Zone for ${esc(name)}">`;
          const sdwanCell = f.physical === false || f.bridge ? "-" :
            `<select data-bind="${bind('interfaces', name, 'sdwan_link_type')}">${SDWAN_TYPES.map(t => `<option ${t === row.sdwan_link_type ? "selected" : ""}>${t}</option>`).join("")}</select>`;
          return `<tr><td><strong>${esc(name)}</strong></td><td>${roleBadge(f)}</td><td>${esc(["vlan", "bridge"].includes(f.type) ? logicalTarget(name) : (row.pan_interface || "-"))}</td><td>${zoneCell}</td><td>${sdwanCell}</td></tr>`;
        }).join("")}</tbody></table></div>
      <div class="cv-row wz-form">
        <label class="wz-check"><input type="checkbox" data-bind="${bind('sdwan', 'enabled')}" ${wiz.state.sdwan.enabled ? "checked" : ""}> Enable SD-WAN for links marked above</label>
        <label class="cv-field"><span>SD-WAN zone</span><input type="text" data-bind="${bind('sdwan', 'zone')}" value="${esc(wiz.state.sdwan.zone)}"></label>
      </div>`;
    },
    vpn() {
      const gateways = wiz.result.gateways, tunnels = wiz.result.tunnels;
      const options = wiz.result.options.gateway_interfaces;
      if (!gateways.length && !tunnels.length) return `<p class="wz-hint">No site-to-site IPsec in the source.</p>`;
      return `<p class="wz-hint">PAN-OS binds every IKE gateway to a local interface and every tunnel to a tunnel.N interface in a zone.</p>
      ${gateways.length ? `<div class="table-wrap wz-table"><table>
        <thead><tr><th>IKE gateway</th><th>Peer</th><th>Source local-address</th><th>Local interface</th></tr></thead>
        <tbody>${gateways.map(g => `<tr><td><strong>${esc(g.name)}</strong></td><td>${esc(g.peer)}</td><td>${esc(g.source_local_address || "-")}</td>
          <td><select data-bind="${bind('ipsec_gateways', g.name, 'local_interface')}"><option value="">Auto (owner of local-address)</option>
          ${options.map(o => `<option ${o === g.local_interface ? "selected" : ""}>${esc(o)}</option>`).join("")}</select></td></tr>`).join("")}</tbody></table></div>` : ""}
      ${tunnels.length ? `<div class="table-wrap wz-table"><table>
        <thead><tr><th>IPsec tunnel</th><th>Zone</th><th>tunnel.N</th></tr></thead>
        <tbody>${tunnels.map(t => `<tr><td><strong>${esc(t.name)}</strong></td>
          <td><input type="text" data-bind="${bind('ipsec_tunnels', t.name, 'zone')}" value="${esc(t.zone)}" placeholder="e.g. VPN"></td>
          <td><input type="number" min="1" max="9999" data-bind="${bind('ipsec_tunnels', t.name, 'tunnel_unit')}" value="${esc(t.tunnel_unit)}"></td></tr>`).join("")}</tbody></table></div>` : ""}`;
    },
    review() {
      const steps = wiz.result.steps;
      const open = steps.filter(s => s.status !== "ok");
      return `<div class="wz-review">
        <ul class="wz-summary">${steps.slice(0, -1).map(s => `<li class="is-${s.status}"><span>${esc(s.label)}</span><strong>${esc(statusText(s))}</strong></li>`).join("")}</ul>
        ${open.length && !(open.length === 1 && open[0].key === "review")
          ? `<p class="wz-blocked">Export opens when every step passes. Still open: ${open.filter(s => s.key !== "review").map(s => esc(s.label)).join(", ")}.</p>`
          : `<p class="wz-ready">All steps passed Keystone's checks.</p>`}
        <p class="wz-hint">Keystone checks references and the rules it knows. Only PAN-OS can confirm a commit: load the file on a lab or the target firewall and run <code>validate full</code> before cutover.</p>
        <div class="wz-review-actions">
          <a class="primary-button ${wiz.result.ready ? "" : "is-disabled"}" id="wizard-download" ${wiz.result.ready ? `href="${esc(downloadUrl())}"` : `aria-disabled="true"`}>Download PAN-OS config</a>
          <button type="button" class="secondary-button" id="wizard-copy">Copy output</button>
        </div>
        <article class="code-panel"><header><div><strong>Generated configuration</strong><span>${wiz.result.output_lines} lines</span></div></header><pre id="wizard-output">${esc(wiz.result.output_text)}</pre></article>
      </div>`;
    },
  };

  function readOnlyEditor(step) {
    return `<p class="wz-hint">This step comes straight from the source export: there is nothing to pick here. Fix an issue in an earlier step (port, zone) or in the source, then re-check.</p>`;
  }

  function bind(...parts) { return esc(JSON.stringify(parts)); }

  function setPath(path, value) {
    const parts = JSON.parse(path);
    let node = wiz.state;
    for (let i = 0; i < parts.length - 1; i += 1) {
      if (node[parts[i]] === undefined) return;
      node = node[parts[i]];
    }
    node[parts[parts.length - 1]] = value;
  }

  function bindEditor(stepKey) {
    const editor = $("wizard-editor");
    editor.querySelectorAll("[data-bind]").forEach(control => {
      const handler = () => {
        let value = control.type === "checkbox" ? control.checked : control.value;
        if (control.type === "number") value = String(value).trim();
        setPath(control.dataset.bind, value);
        if (control.dataset.bind === JSON.stringify(["deployment", "panorama"])) $("wz-panorama-names")?.classList.toggle("hidden", !value);
        if (control.dataset.rerender && control.type !== "number") {
          $("wizard-editor").innerHTML = EDITORS[stepKey](wiz.result.steps[wiz.current]);
          bindEditor(stepKey);
        } else if (control.dataset.rerender) {
          const cell = control.closest("tr")?.querySelector("code.wz-result");
          const name = JSON.parse(control.dataset.bind)[1];
          if (cell) cell.textContent = logicalTarget(name);
        }
        // Any edit invalidates this step's last result until it is re-checked.
        const status = $("wizard-step-status");
        status.className = "wz-status is-stale";
        status.textContent = "Changed, not checked yet";
        wiz.dirty = true;
      };
      control.addEventListener(control.tagName === "SELECT" || control.type === "checkbox" ? "change" : "input", handler);
    });
    if (stepKey === "review") {
      $("wizard-copy")?.addEventListener("click", () => window.NES.copyText(wiz.result.output_text));
      $("wizard-download")?.addEventListener("click", async event => {
        if (!wiz.result.ready) { event.preventDefault(); return; }
        if (wiz.dirty) {
          event.preventDefault();
          if ((await validate(false)) && wiz.result.ready) window.location.href = downloadUrl();
        }
      });
    }
  }
})();
