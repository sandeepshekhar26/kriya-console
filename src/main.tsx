import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

// Apply the saved theme before first paint so there's no flash. Light is the first-class default
// (the :root tokens), so only a stored "dark" preference sets the attribute here.
if (localStorage.getItem("kriya-console:theme") === "dark") {
  document.documentElement.setAttribute("data-theme", "dark");
}

const root = document.getElementById("root");
if (!root) throw new Error("missing #root element");
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
