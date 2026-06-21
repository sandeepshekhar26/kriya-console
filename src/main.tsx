import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

// Apply the saved theme before first paint so there's no flash. Dark is the default
// (the :root tokens), so only a stored "light" preference sets the attribute here.
if (localStorage.getItem("kriya-console:theme") === "light") {
  document.documentElement.setAttribute("data-theme", "light");
}

const root = document.getElementById("root");
if (!root) throw new Error("missing #root element");
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
