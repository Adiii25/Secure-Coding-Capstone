// Client-side helpers. The server re-validates everything, so this only improves usability.
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  var RULES = {
    name: [/^[A-Za-z]+(?: [A-Za-z]+)*$/, "Use letters and single spaces only (2-60 characters).", 2],
    email: [/^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/, "Enter a valid email address."],
    roll: [/^[A-Za-z0-9]{10,12}$/, "Roll number must be 10 to 12 letters or digits."]
  };

  function check(input) {
    var rule = input.getAttribute("data-rule"), v = input.value, msg = null;
    if (!rule) return true;
    if (rule === "choice") { if (!v) msg = "Choose an option."; }
    else if (rule === "required") { if (!v) msg = "This field is required."; }
    else if (rule === "password") {
      if (v.length < 8) msg = "Use at least 8 characters.";
      else if (!/[A-Za-z]/.test(v) || !/\d/.test(v)) msg = "Include at least one letter and one digit.";
    } else if (rule.indexOf("match:") === 0) {
      var other = document.getElementById(rule.slice(6));
      if (v !== (other ? other.value : "")) msg = "Passwords do not match.";
    } else if (RULES[rule]) {
      var s = input.value.trim();
      if (!RULES[rule][0].test(s) || (RULES[rule][2] && s.length < RULES[rule][2])) msg = RULES[rule][1];
    }
    show(input, msg);
    return !msg;
  }

  function show(input, msg) {
    var p = document.getElementById(input.id + "-msg");
    input.setAttribute("aria-invalid", msg ? "true" : "false");
    if (!p) return;
    p.textContent = msg || p.getAttribute("data-hint") || "";
    p.className = "msg" + (msg ? " err" : "");
  }

  // Show / hide password
  $$("[data-reveal]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-reveal"));
      var hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      if (hidden) input.setAttribute("data-revealed", ""); else input.removeAttribute("data-revealed");
      btn.textContent = hidden ? "Hide" : "Show";
      btn.setAttribute("aria-label", (hidden ? "Hide " : "Show ") + input.labels[0].textContent.toLowerCase());
    });
  });

  // Password strength meter
  $$("[data-meter]").forEach(function (meter) {
    var input = document.getElementById(meter.getAttribute("data-meter"));
    input.addEventListener("input", function () {
      var v = input.value, score = 0;
      if (v.length >= 8) score++;
      if (v.length >= 12) score++;
      if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score++;
      if (/\d/.test(v) && /[^A-Za-z0-9]/.test(v)) score++;
      if (!v) score = 0;
      meter.className = "meter" + (score ? " s" + score : "");
    });
  });

  // Live validation: after the first blur, re-check on every keystroke
  $$("form[data-validate]").forEach(function (form) {
    var inputs = $$("[data-rule]", form);
    inputs.forEach(function (input) {
      var touched = false;
      input.addEventListener("blur", function () { if (input.value || touched) { touched = true; check(input); } });
      input.addEventListener("input", function () {
        if (input.getAttribute("data-rule") === "roll") input.value = input.value.toUpperCase();
        if (touched) check(input);
        var confirm = $$("[data-rule^='match:" + input.id + "']", form)[0];
        if (confirm && confirm.value) check(confirm);
      });
      input.addEventListener("change", function () { if (input.tagName === "SELECT") check(input); });
    });
    form.addEventListener("submit", function (e) {
      var firstBad = null;
      inputs.forEach(function (i) { if (!check(i) && !firstBad) firstBad = i; });
      if (firstBad) { e.preventDefault(); firstBad.focus(); return; }
      var btn = $("button[type=submit]", form);
      if (btn) setTimeout(function () { btn.disabled = true; }, 0);   // stop double submits
    });
  });

  // Session countdown, warning dialog and "stay signed in"
  var expires = document.body.getAttribute("data-expires");
  if (expires === null) return;
  var deadline = Date.now() + parseInt(expires, 10) * 1000;
  var chip = $("[data-countdown]"), dlg = $("#timeout-dialog"), dlgCount = $("[data-dialog-countdown]");
  function fmt(s) { return ("0" + Math.floor(s / 60)).slice(-2) + ":" + ("0" + (s % 60)).slice(-2); }
  function tick() {
    var left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
    if (chip) { chip.textContent = fmt(left); chip.parentNode.classList.toggle("low", left <= 60); }
    if (dlgCount) dlgCount.textContent = left;
    if (left <= 60 && left > 0 && dlg && !dlg.open && dlg.showModal) dlg.showModal();
    if (left === 0) { window.location.href = "/login"; }
  }
  setInterval(tick, 1000); tick();
  var extend = $("[data-extend]");
  if (extend) extend.addEventListener("click", function () {
    fetch("/session/extend", { method: "POST", headers: { "X-CSRF-Token": document.body.getAttribute("data-csrf") }, credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error("expired"); return r.json(); })
      .then(function (d) { deadline = Date.now() + d.expires_in * 1000; dlg.close(); tick(); })
      .catch(function () { window.location.href = "/login"; });
  });
})();
