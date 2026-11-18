// Sets the saved colour theme before the page paints, so a light-theme user never sees a dark flash.
// A separate file (not an inline script) lets the content security policy forbid inline scripts.
(function () {
  try {
    var theme = localStorage.getItem("nes-theme") || "dark";
    document.documentElement.setAttribute("data-theme", theme);
  } catch (error) { /* storage blocked: keep the default theme */ }
})();
