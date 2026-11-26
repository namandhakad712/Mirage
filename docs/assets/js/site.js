/*
 * Mirage documentation — site behavior.
 *
 * Four small, independent, dependency-free behaviors. Every one is wrapped
 * defensively: this script must never throw, on any browser, in any theme.
 *   1. Theme toggle (button + localStorage + prefers-color-scheme).
 *   2. Mobile navigation and sidebar drawer.
 *   3. Table of contents builder + scroll spy (right rail).
 *   4. Copy buttons on code blocks.
 */
(function () {
  "use strict";

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {

    /* ---------- 1. Theme toggle ---------- */

    try {
      var toggle = document.getElementById("theme-toggle");
      if (toggle) {
        toggle.addEventListener("click", function () {
          var root = document.documentElement;
          var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
          root.setAttribute("data-theme", next);
          try { localStorage.setItem("mirage-theme", next); } catch (e) { /* private mode */ }
        });
      }
    } catch (e) { /* no theme toggle: fine */ }

    /* ---------- 2. Mobile nav + sidebar drawer ---------- */

    try {
      var navToggle = document.getElementById("nav-toggle");
      var siteNav = document.getElementById("site-nav");
      if (navToggle && siteNav) {
        navToggle.addEventListener("click", function () {
          var open = siteNav.classList.toggle("open");
          navToggle.setAttribute("aria-expanded", open ? "true" : "false");
        });
      }

      var sidebar = document.getElementById("sidebar");
      var backdrop = document.getElementById("sidebar-backdrop");
      // On narrow screens the sidebar becomes a drawer opened from the
      // header menu button; the same button opens both.
      if (navToggle && sidebar && backdrop) {
        navToggle.addEventListener("click", function () {
          var open = sidebar.classList.toggle("open");
          backdrop.hidden = !open;
        });
        backdrop.addEventListener("click", function () {
          sidebar.classList.remove("open");
          backdrop.hidden = true;
        });
      }
      // Close drawer after following a link.
      if (sidebar) {
        sidebar.addEventListener("click", function (ev) {
          if (ev.target && ev.target.tagName === "A") {
            sidebar.classList.remove("open");
            if (backdrop) backdrop.hidden = true;
          }
        });
      }
    } catch (e) { /* navigation stays simple */ }

    /* ---------- 3. Table of contents + scroll spy ---------- */

    try {
      var content = document.getElementById("doc-content");
      var tocList = document.getElementById("toc-list");
      if (content && tocList) {
        var headings = content.querySelectorAll("h2, h3");
        var links = [];
        Array.prototype.forEach.call(headings, function (h, i) {
          if (!h.id) h.id = h.textContent.trim().toLowerCase()
            .replace(/[^\w\s-]/g, "").replace(/\s+/g, "-") + (i ? "-" + i : "");
          var a = document.createElement("a");
          a.href = "#" + h.id;
          a.textContent = h.textContent;
          a.className = h.tagName === "H3" ? "toc-h3" : "";
          var li = document.createElement("li");
          li.appendChild(a);
          tocList.appendChild(li);
          links.push({ a: a, h: h });
        });

        if (links.length && "IntersectionObserver" in window) {
          var active = null;
          var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
              if (entry.isIntersecting) {
                if (active) active.a.classList.remove("toc-active");
                var hit = null;
                for (var j = 0; j < links.length; j++) {
                  if (links[j].h === entry.target) { hit = links[j]; break; }
                }
                if (hit) { hit.a.classList.add("toc-active"); active = hit; }
              }
            });
          }, { rootMargin: "-15% 0px -70% 0px", threshold: 0 });
          links.forEach(function (l) { io.observe(l.h); });
        }
      }
    } catch (e) { /* no TOC: the page is still fully readable */ }

    /* ---------- 4. Copy buttons on code blocks ---------- */

    try {
      var blocks = document.querySelectorAll(".doc-content .highlight");
      Array.prototype.forEach.call(blocks, function (block) {
        // Skip blocks that already carry a header.
        if (block.querySelector(".code-header")) return;
        var pre = block.querySelector("pre");
        if (!pre) return;

        var header = document.createElement("div");
        header.className = "code-header";

        var label = document.createElement("span");
        label.className = "code-lang";
        label.textContent = "code";
        header.appendChild(label);

        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "code-copy";
        btn.setAttribute("aria-label", "Copy code to clipboard");
        btn.textContent = "Copy";

        btn.addEventListener("click", function () {
          var done = function () {
            btn.textContent = "Copied";
            btn.setAttribute("aria-label", "Copied");
            setTimeout(function () {
              btn.textContent = "Copy";
              btn.setAttribute("aria-label", "Copy code to clipboard");
            }, 1600);
          };
          var text = pre.innerText;
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done, done);
          } else {
            // Legacy path: never fail the click.
            var ta = document.createElement("textarea");
            ta.value = text;
            ta.setAttribute("readonly", "");
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand("copy"); } catch (e2) { /* best effort */ }
            document.body.removeChild(ta);
            done();
          }
        });

        header.appendChild(btn);
        block.insertBefore(header, block.firstChild);
      });
    } catch (e) { /* copy buttons are enhancement only */ }

  });
})();
