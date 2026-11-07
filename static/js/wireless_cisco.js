// Wireless Analyzer: controller picker and the Cisco 9800 workspace.
// Huawei keeps wireless.js as it was; Cisco renders its own tables here.
(() => {
  const root = document.getElementById("wireless-root");
  if (!root || root.dataset.ready) return;
  root.dataset.ready = "1";
  const esc = (v) => window.NES.escape(v ?? "");
  const $ = (id) => document.getElementById(id);
  const NAMES = { Huawei: "Huawei WLC", Cisco: "Cisco Catalyst 9800" };
  const TEXT = {
    Huawei: { delta: "Huawei to Huawei. Source is the reference.", "role-file": "AP Info CSV/XLSX or display ap all TXT",
      "role-intro": "Match Controller A and Controller B operational inventories by MAC, serial, then AP name. Capture both WLCs within 1–2 minutes." },
    Cisco: { delta: "9800 to 9800. show tech-support wireless works: only its running-config is compared.",
      "role-file": "show tech-support wireless or show ap summary TXT, or CSV",
      "role-intro": "A 9800 AP is registered on one controller and absent from the other (N+1 or SSO). Keystone flags APs on both or on neither, and Policy / Site / RF Tag differences." },
  };

  // ------------------------------------------------------------ controller picker
  function choose(vendor, remember = true) {
    root.dataset.vendor = vendor;
    $("wireless-vendor-picker").classList.add("hidden");
    $("wireless-vendor-bar").classList.remove("hidden");
    $("wireless-vendor-area").classList.remove("hidden");
    $("wireless-vendor-name").textContent = NAMES[vendor];
    ["delta-vendor", "ap-role-vendor", "analysis-vendor"].forEach((id) => { if ($(id)) $(id).value = vendor; });
    const master = $("master-vendor"), validation = $("validation-vendor");
    if (master) { master.value = vendor; master.dispatchEvent(new Event("change")); }
    if (validation) validation.value = vendor;
    document.querySelectorAll("[data-vendor-text]").forEach((el) => { el.textContent = TEXT[vendor][el.dataset.vendorText] || el.textContent; });
    document.querySelectorAll("[data-vendor-only]").forEach((el) => el.classList.toggle("hidden", el.dataset.vendorOnly !== vendor));
    try { if (remember) localStorage.setItem("keystone.wireless.vendor", vendor); } catch (e) { /* convenience only */ }
    const current = document.querySelector("[data-wireless-workspace].active")?.dataset.wirelessWorkspace || "analysis";
    window.NESWireless?.setWorkspace(current, false);
  }
  function reset() {
    delete root.dataset.vendor;
    $("wireless-vendor-picker").classList.remove("hidden");
    $("wireless-vendor-bar").classList.add("hidden");
    $("wireless-vendor-area").classList.add("hidden");
    try { localStorage.removeItem("keystone.wireless.vendor"); } catch (e) { /* convenience only */ }
  }
  document.querySelectorAll("[data-vendor-pick]").forEach((b) => b.addEventListener("click", () => choose(b.dataset.vendorPick)));
  $("wireless-vendor-change").addEventListener("click", reset);
  let saved = null;
  try { saved = localStorage.getItem("keystone.wireless.vendor"); } catch (e) { saved = null; }
  const asked = new URLSearchParams(location.search).get("vendor");
  const start = NAMES[asked] ? asked : NAMES[saved] ? saved : null;
  if (start) choose(start, false);

  // ------------------------------------------------------------ Cisco workspace
  const form = $("cisco-form");
  if (!form) return;
  const fileLabel = (input, label, fallback) => input.addEventListener("change", () => {
    $(label).textContent = input.files[0]?.name || fallback;
    input.closest(".drop-zone")?.classList.toggle("has-file", Boolean(input.files.length));
  });
  fileLabel($("cisco-config-file"), "cisco-config-label", "TXT or LOG");
  fileLabel($("cisco-inventory-file"), "cisco-inventory-label", "CSV or XLSX");

  const yes = (v) => (v === true ? "Yes" : v === false ? "No" : v);
  function table(id, cols, rows, empty = "No data in this capture.") {
    const head = `<thead><tr>${cols.map((c) => `<th>${esc(c[1])}</th>`).join("")}</tr></thead>`;
    const body = rows.length ? rows.map((r) => `<tr>${cols.map(([k, , fmt]) => {
      const raw = typeof k === "function" ? k(r) : r[k];
      if (fmt === "config") {
        const lines = raw || [];
        return `<td><details class="vap-config-preview"><summary>${lines.length} line${lines.length === 1 ? "" : "s"}</summary><code>${lines.map(esc).join("\n")}</code></details></td>`;
      }
      const v = Array.isArray(raw) ? raw.join(", ") : yes(raw);
      return fmt === "status" ? `<td><span class="cell-status" data-state="${esc(String(v).toLowerCase())}">${esc(v)}</span></td>` : `<td>${esc(v)}</td>`;
    }).join("")}</tr>`).join("") : `<tr><td colspan="${cols.length}">${esc(empty)}</td></tr>`;
    $(id).innerHTML = head + `<tbody>${body}</tbody>`;
  }
  const kv = (pairs) => pairs.filter(([, v]) => v !== "" && v != null).map(([k, v]) => `<div><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join("");

  function switchTab(name) {
    document.querySelectorAll("#cisco-tabs [data-cisco-tab]").forEach((b) => b.classList.toggle("active", b.dataset.ciscoTab === name));
    document.querySelectorAll(".cisco-tab").forEach((p) => p.classList.toggle("active", p.dataset.ciscoPanel === name));
  }
  $("cisco-tabs").addEventListener("click", (e) => { const b = e.target.closest("[data-cisco-tab]"); if (b) switchTab(b.dataset.ciscoTab); });

  function render(result, sourceName) {
    const m = result.cisco, w = m.wlc, c = result.cards, sev = result.severity || {};
    $("cisco-empty").classList.add("hidden");
    $("cisco-result").classList.remove("hidden");
    $("cisco-source-name").textContent = sourceName;
    $("cisco-platform").textContent = ` · ${w.model || "Catalyst 9800"} · IOS XE ${w.software_version || "?"} · ${m.source_kind}`;
    $("cisco-export").href = result.export_url;
    const asBuilt = $("cisco-as-built");
    asBuilt.classList.toggle("hidden", !result.as_built_url);
    if (result.as_built_url) asBuilt.href = result.as_built_url;
    const cards = [["APs", c.total_aps], ["Registered", c.registered], ["WLANs up", `${c.wlans_up} / ${c.wlans}`],
      ["Policy Tags", c.policy_tags], ["Policy Profiles", c.policy_profiles], ["Critical / Warning", `${sev.Critical || 0} / ${sev.Warning || 0}`]];
    $("cisco-summary").innerHTML = cards.map(([k, v]) => `<article><span>${esc(k)}</span><strong>${esc(v)}</strong></article>`).join("");

    $("cisco-wlc").innerHTML = kv([["Hostname", w.hostname], ["Model", w.model], ["Serial", (w.serials || []).join(", ")],
      ["Software", w.software_version], ["Uptime", w.uptime], ["Management", [w.management_interface, w.management_ip].filter(Boolean).join(" · ")],
      ["HA", [w.ha_mode, w.ha_hardware].filter(Boolean).join(" · ")], ["Switchovers", w.switchovers], ["Mobility group", w.mobility_group],
      ["Country", w.country], ["Max APs / clients", [w.max_aps, w.max_clients].filter(Boolean).join(" / ")]]);
    $("cisco-states").innerHTML = Object.entries(result.status_counts || {}).map(([k, v]) =>
      `<div><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join("") || "<p>No AP data.</p>";
    const radios = (w.radios || []).map((r) => `<tr><td>${esc(r.band)}</td><td>${r.total}</td><td>${r.up}</td><td>${r.down}</td></tr>`).join("");
    const lic = (w.licenses || []).map((l) => `<tr><td>${esc(l.license)}</td><td>${esc(l.entitlement)}</td><td>${esc(l.count)}</td><td>${esc(l.status)}</td></tr>`).join("");
    $("cisco-radios").innerHTML = (radios ? `<div class="table-wrap"><table><thead><tr><th>Band</th><th>Radios</th><th>Up</th><th>Down</th></tr></thead><tbody>${radios}</tbody></table></div>` : "")
      + (lic ? `<div class="table-wrap"><table><thead><tr><th>Licence</th><th>Entitlement</th><th>Count</th><th>Status</th></tr></thead><tbody>${lic}</tbody></table></div>` : "")
      || "<p>Not in this capture (needs show wireless summary and show license summary).</p>";
    const ds = result.ap_device_summary || {};
    $("cisco-device-summary").innerHTML = (ds.rows || []).length ? `<div class="table-wrap"><table><thead><tr><th>Model</th><th>APs</th><th>Software</th><th>Consistency</th></tr></thead><tbody>${
      ds.rows.map((r) => `<tr><td>${esc(r.model)}</td><td>${esc(r.total)}</td><td>${esc((r.versions || []).map((v) => `${v.version} (${v.count})`).join(", "))}</td><td>${esc(r.consistency)}</td></tr>`).join("")}</tbody></table></div>` : "<p>No AP data.</p>";

    $("cisco-findings").innerHTML = (result.findings || []).map((f) => `
      <details class="cisco-finding sev-${esc(f.severity.toLowerCase())}" ${f.severity === "Critical" ? "open" : ""}>
        <summary><span class="sev">${esc(f.severity)}</span><span class="cat">${esc(f.category)}</span><strong>${esc(f.title)}</strong></summary>
        <p>${esc(f.detail)}</p>${f.items.length ? `<ul>${f.items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>` : ""}
      </details>`).join("") || `<div class="empty-state compact">No findings. The tags, WLANs and APs line up.</div>`;

    table("cisco-ap-table", [["name", "AP Name"], ["model", "Model"], ["mac", "Ethernet MAC"], ["serial", "Serial"], ["ip", "IP"],
      ["state", "State", "status"], ["mode", "Mode"], ["policy_tag", "Policy Tag"], ["site_tag", "Site Tag"], ["rf_tag", "RF Tag"],
      ["misconfigured", "Misconfigured"], ["version", "Software"], ["primary_wlc", "Primary WLC"], ["secondary_wlc", "Secondary WLC"],
      ["location", "Location"], ["disconnect_reason", "Last disconnect"]], m.aps);
    $("cisco-ap-count").textContent = `${m.aps.length} APs`;
    table("cisco-wlan-table", [["id", "ID"], ["profile", "Profile"], ["ssid", "SSID"], ["status", "Status", "status"],
      [(x) => x.security_summary || x.security, "Security"], ["auth_list", "802.1X list"], ["mac_filtering", "MAC filtering"],
      ["broadcast", "Broadcast"], ["radio_policy", "Radio"], ["ft", "Fast transition"], ["psk", "PSK"], ["config", "Config", "config"]], m.wlans);
    const delivery = [];
    m.wlans.forEach((x) => {
      const tags = m.policy_tags.filter((t) => t.mappings.some((mp) => mp.wlan === x.profile));
      const aps = m.aps.filter((a) => tags.some((t) => t.name === a.policy_tag)).length;
      delivery.push({ ssid: `${x.ssid} (${x.profile})`, tags: tags.map((t) => t.name), policies: [...new Set(tags.flatMap((t) => t.mappings.filter((mp) => mp.wlan === x.profile).map((mp) => mp.policy)))], aps });
    });
    table("cisco-wlan-delivery", [["ssid", "WLAN"], ["tags", "Policy Tags"], ["policies", "Policy Profiles"], ["aps", "APs broadcasting"]], delivery);
    table("cisco-policy-table", [["name", "Name"], ["description", "Description"], ["status", "Status", "status"], ["vlan", "VLAN"],
      ["switching", "Switching"], ["dhcp", "DHCP"], ["auth", "Auth"], ["aaa_override", "AAA override"], ["nac", "NAC"],
      ["accounting", "Accounting"], ["session_timeout", "Session timeout"], ["idle_timeout", "Idle timeout"], ["acl", "ACL"], ["config", "Config", "config"]], m.policy_profiles);
    const tagRows = m.policy_tags.flatMap((t) => (t.mappings.length ? t.mappings : [{ wlan: "-", policy: "-" }]).map((mp) => ({
      tag: t.name, description: t.description, wlan: mp.wlan, policy: mp.policy, aps: m.aps.filter((a) => a.policy_tag === t.name).length })));
    table("cisco-ptag-table", [["tag", "Policy Tag"], ["description", "Description"], ["wlan", "WLAN profile"], ["policy", "Policy Profile"], ["aps", "APs on tag"]], tagRows);
    table("cisco-stag-table", [["name", "Site Tag"], ["description", "Description"], ["ap_profile", "AP Join Profile"], ["flex_profile", "Flex Profile"],
      [(t) => (t.local_site ? "Local" : "FlexConnect"), "Site type"], [(t) => m.aps.filter((a) => a.site_tag === t.name).length, "APs"]], m.site_tags);
    table("cisco-rtag-table", [["name", "RF Tag"], ["description", "Description"], ["rf_24", "2.4 GHz profile"], ["rf_5", "5 GHz profile"], ["rf_6", "6 GHz profile"],
      [(t) => m.aps.filter((a) => a.rf_tag === t.name).length, "APs"]], m.rf_tags);
    table("cisco-join-table", [["name", "Name"], ["description", "Description"], ["country", "Country"], ["mgmt_user", "Mgmt user"], ["ssh", "SSH"],
      ["ntp", "NTP"], ["syslog", "Syslog"], ["primary", "Backup primary"], ["secondary", "Backup secondary"], ["config", "Config", "config"]], m.ap_join_profiles);
    table("cisco-flex-table", [["name", "Name"], ["description", "Description"], ["native_vlan", "Native VLAN"], ["vlans", "VLANs"], ["acls", "ACLs"], ["config", "Config", "config"]], m.flex_profiles);
    table("cisco-rf-table", [["name", "Name"], ["band", "Band"], ["description", "Description"], ["tx_min", "Tx min"], ["tx_max", "Tx max"],
      ["rx_sop", "RX-SOP"], ["mandatory", "Mandatory rates"], ["status", "Status", "status"], ["config", "Config", "config"]], m.rf_profiles);
    table("cisco-aaa-table", [["name", "Name"], ["type", "Type"], ["address", "Address"], ["ports", "Ports"]], m.aaa.servers);
    table("cisco-aaa-groups", [["name", "Group / method"], ["type", "Type"], ["servers", "Servers"]],
      [...m.aaa.groups, ...m.aaa.methods.map((x) => ({ name: x, type: "Method list", servers: "" }))]);
    table("cisco-user-table", [["username", "Username"], ["privilege", "Privilege"], ["credential", "Credential"]], m.local_users);

    const dv = result.deployment_validation;
    const hasDv = dv && dv.summary;
    $("cisco-deploy-empty").classList.toggle("hidden", !!hasDv);
    $("cisco-deploy").classList.toggle("hidden", !hasDv);
    if (hasDv) {
      const s = dv.summary;
      $("cisco-deploy-summary").innerHTML = [["Planned", s.planned], ["Matched", s.matched], ["Validated", s.validated], ["Mismatch", s.mismatch], ["Missing", s.missing], ["Unexpected", s.unexpected]]
        .map(([k, v]) => `<article><span>${k}</span><strong>${v || 0}</strong></article>`).join("");
      table("cisco-deploy-table", [["ap_name", "Planned AP"], ["actual_ap_name", "Actual AP"], ["mac_address", "Planned MAC"], ["actual_mac", "Actual MAC"],
        ["serial_number", "Planned serial"], ["actual_serial", "Actual serial"], ["actual_group", "Actual Policy Tag"], ["actual_status", "Actual state", "status"],
        ["match_method", "Match by"], ["validation_status", "Validation", "status"], ["mismatch_fields", "Mismatch"]], dv.rows || []);
      table("cisco-unexpected-table", [[1, "AP Name"], [2, "Serial"], [3, "MAC"], [4, "IP"], [5, "Policy Tag"], [6, "State", "status"]], dv.unexpected_aps || []);
    }
    switchTab((sev.Critical || sev.Warning) ? "findings" : "overview");
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = $("cisco-analyze-button");
    window.NES.setLoading(button, true, "Analyzing...");
    try {
      const res = await fetch("/wireless/api/analyze", { method: "POST", body: new FormData(form) });
      const payload = await res.json();
      if (!res.ok || !payload.ok) throw new Error(payload.error || "Analysis failed.");
      render(payload.result, payload.result.source_name);
      window.NES.toast("9800 analysis completed.");
    } catch (err) { window.NES.toast(err.message, "error"); }
    finally { window.NES.setLoading(button, false); }
  });
})();
