(function () {
  "use strict";

  // ----- Theme toggle -----
  var themeToggle = document.querySelector(".theme-toggle");
  if (themeToggle) {
    var root = document.documentElement;
    var darkQuery = window.matchMedia("(prefers-color-scheme: dark)");

    function currentTheme() {
      var explicit = root.getAttribute("data-theme");
      if (explicit === "light" || explicit === "dark") return explicit;
      return darkQuery.matches ? "dark" : "light";
    }

    function applyTheme(theme, persist) {
      if (theme === "light" || theme === "dark") {
        root.setAttribute("data-theme", theme);
      } else {
        root.removeAttribute("data-theme");
      }
      if (persist) {
        try {
          if (theme === "light" || theme === "dark") {
            localStorage.setItem("docs-theme", theme);
          } else {
            localStorage.removeItem("docs-theme");
          }
        } catch (e) { /* ignore */ }
      }
      themeToggle.setAttribute(
        "aria-label",
        currentTheme() === "dark" ? "Switch to light theme" : "Switch to dark theme"
      );
    }

    themeToggle.addEventListener("click", function () {
      applyTheme(currentTheme() === "dark" ? "light" : "dark", true);
    });

    // If the user hasn't picked an override, follow the system as it changes.
    darkQuery.addEventListener("change", function () {
      if (!root.getAttribute("data-theme")) {
        applyTheme(null, false);
      }
    });

    // Set the initial aria-label based on the resolved theme.
    applyTheme(root.getAttribute("data-theme") || null, false);
  }

  // ----- Mobile sidebar -----
  var toggle = document.querySelector(".menu-toggle");
  var sidebar = document.getElementById("sidebar");
  var backdrop = document.querySelector(".sidebar-backdrop");
  if (!toggle || !sidebar || !backdrop) return;

  function setOpen(open) {
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    sidebar.classList.toggle("open", open);
    backdrop.classList.toggle("open", open);
    backdrop.hidden = !open;
    document.body.classList.toggle("menu-open", open);
  }

  function isMobile() {
    return window.matchMedia("(max-width: 900px)").matches;
  }

  toggle.addEventListener("click", function () {
    var open = toggle.getAttribute("aria-expanded") !== "true";
    setOpen(open);
  });

  backdrop.addEventListener("click", function () {
    setOpen(false);
  });

  // Close the menu after tapping a sidebar link on mobile.
  sidebar.addEventListener("click", function (event) {
    var target = event.target;
    while (target && target !== sidebar) {
      if (target.tagName === "A") {
        if (isMobile()) setOpen(false);
        break;
      }
      target = target.parentNode;
    }
  });

  // Close with Escape.
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
      setOpen(false);
      toggle.focus();
    }
  });

  // Reset state when resizing back to desktop.
  window.addEventListener("resize", function () {
    if (!isMobile() && toggle.getAttribute("aria-expanded") === "true") {
      setOpen(false);
    }
  });
})();
