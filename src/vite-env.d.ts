/// <reference types="vite/client" />

// Build-time flag injected by Vite `define` (see vite.config.ts). `true` only in a `KRIYA_DEMO=1`
// web/demo build; `false` (and thus tree-shaken) in the shipped desktop build.
declare const __KRIYA_DEMO__: boolean;
