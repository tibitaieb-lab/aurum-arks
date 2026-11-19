"use strict";
(() => {
  const theme = document.getElementById("theme");
  const themes = new Set(Array.from(theme?.options || [], o => o.value));
  const preferenceKey = document.documentElement.dataset.themePreferenceKey || "arks-theme";
  let restored = "classic-light";
  try { const saved = localStorage.getItem(preferenceKey); if (themes.has(saved)) restored = saved; } catch (_) {}
  document.documentElement.dataset.theme = restored;
  if (theme) {
    theme.value = restored;
    theme.addEventListener("change", () => {
      if (!themes.has(theme.value)) return;
      document.documentElement.dataset.theme = theme.value;
      try { localStorage.setItem(preferenceKey, theme.value); document.documentElement.dataset.themePersistence = "saved"; }
      catch (_) { document.documentElement.dataset.themePersistence = "unavailable"; }
    });
  }
  const close = document.querySelector('form[action="/_arks/close"]');
  if (close) {
    const status = close.previousElementSibling;
    if (status?.textContent === "ARKS V1 · READY") { status.className = "ready-badge"; document.getElementById("header-controls").prepend(status); }
    document.getElementById("header-controls").append(close);
  }
  document.querySelectorAll('form[action="/documents/upload"]').forEach(form => {
    form.id = form.querySelector('input[multiple]') ? "upload-multiple" : "upload-single";
  });
  const table = document.getElementById("source-table"); if (!table) return;
  const normalize = value => String(value).normalize("NFC").trim().toLocaleLowerCase("fr");
  const compare = new Intl.Collator("fr", {numeric:true, sensitivity:"variant"}).compare;
  const rows = Array.from(table.tBodies[0].rows, (node, index) => ({node, index, values:JSON.parse(node.dataset.values), categories:JSON.parse(node.dataset.categories), consultable:node.dataset.consultable === "true"}));
  const scope = document.getElementById("catalogue-scope");
  const source = document.getElementById("filter-source"), candidate = document.getElementById("filter-candidate");
  const binary = document.getElementById("filter-binary"), original = document.getElementById("filter-original");
  const coverage = document.getElementById("filter-coverage"), category = document.getElementById("filter-category");
  let sortColumn = 0, sortDirection = 1, lastClicked = null;
  const scoped = () => rows.filter(r => scope.value === "all" || r.consultable);
  const selected = field => Array.from(field.querySelectorAll("input:checked"), x => x.value);
  const options = (select, values) => { select.replaceChildren(new Option("Tous", "")); [...new Set(values)].sort(compare).forEach(value => select.add(new Option(value, value))); };
  function checks(details, values) {
    const field = details.querySelector("fieldset"), legend = field.querySelector("legend"); field.replaceChildren(legend);
    [...new Set(values)].sort(compare).forEach(value => {
      const label = document.createElement("label"), input = document.createElement("input"), text = document.createElement("span");
      input.type = "checkbox"; input.value = value; text.textContent = value; label.append(input, text); field.append(label);
    }); details.querySelector(".filter-toggle").textContent = "Tous";
  }
  function populate() {
    const pool = scoped(); options(binary, pool.map(r => r.values[2])); options(original, pool.map(r => r.values[5]));
    checks(coverage, pool.map(r => r.values[3])); checks(category, pool.flatMap(r => r.categories));
  }
  function apply() {
    const allowed = scoped(), a = normalize(source.value), b = normalize(candidate.value), covers = selected(coverage), cats = selected(category);
    const matches = allowed.filter(r => normalize(r.values[0]).includes(a) && normalize(r.values[1]).includes(b)
      && (!binary.value || r.values[2] === binary.value) && (!original.value || r.values[5] === original.value)
      && (!covers.length || covers.includes(r.values[3])) && (!cats.length || r.categories.some(c => cats.includes(c))));
    matches.sort((x,y) => sortDirection * compare(x.values[sortColumn], y.values[sortColumn]) || x.index - y.index);
    rows.forEach(r => { r.node.hidden = true; });
    const fragment = document.createDocumentFragment(); matches.forEach(r => { r.node.hidden = false; fragment.append(r.node); }); table.tBodies[0].append(fragment);
    document.getElementById("result-count").textContent = `${matches.length} sources affichées / ${allowed.length}`;
    document.getElementById("empty-results").hidden = matches.length !== 0;
    [coverage, category].forEach(field => { const n = selected(field).length; field.querySelector(".filter-toggle").textContent = n ? `${n} sélection${n > 1 ? "s" : ""}` : "Tous"; });
    table.querySelectorAll("th").forEach((th,i) => { th.setAttribute("aria-sort", i === sortColumn ? (sortDirection === 1 ? "ascending" : "descending") : "none"); th.querySelector(".sort-mark").textContent = i === sortColumn ? (sortDirection === 1 ? "↑" : "↓") : "↕"; });
  }
  source.addEventListener("input", apply); candidate.addEventListener("input", apply);
  function setOpen(field, open) { field.querySelector("fieldset").hidden = !open; field.querySelector(".filter-toggle").setAttribute("aria-expanded", String(open)); }
  [coverage, category].forEach(field => {
    field.querySelector(".filter-toggle").addEventListener("click", () => { const open = field.querySelector("fieldset").hidden; [coverage, category].forEach(other => setOpen(other, other === field && open)); });
    field.addEventListener("keydown", event => { if (event.key === "Escape") { setOpen(field, false); field.querySelector(".filter-toggle").focus(); } });
  });
  document.addEventListener("click", event => [coverage, category].forEach(field => { if (!field.contains(event.target)) setOpen(field, false); }));
  [binary, original, coverage, category].forEach(field => field.addEventListener("change", apply));
  table.querySelectorAll(".sort-button").forEach(button => button.addEventListener("click", () => {
    const next = Number(button.dataset.column); sortDirection = next === lastClicked ? -sortDirection : 1;
    sortColumn = next; lastClicked = next; apply();
  }));
  scope.addEventListener("change", () => { populate(); apply(); });
  document.getElementById("reset-filters").addEventListener("click", () => {
    source.value = candidate.value = ""; scope.value = "consultable"; sortColumn = 0; sortDirection = 1; lastClicked = null;
    populate(); [coverage, category].forEach(field => setOpen(field, false)); apply();
  });
  populate();
  const initial = document.getElementById("catalogue").dataset.initialState;
  if (initial) { scope.value = "all"; populate(); if ([...binary.options].some(o => o.value === initial)) binary.value = initial; }
  apply();
})();
