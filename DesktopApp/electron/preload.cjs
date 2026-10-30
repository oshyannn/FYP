"use strict";
// The ONLY things the web page can do: send an API request through the main process, and ask to restore a session.
// It never sees the login token or the sign-up secret.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("sb", {
  api: (method, path, body) => ipcRenderer.invoke("api", { method, path, body }),
  restoreSession: () => ipcRenderer.invoke("session:restore"),
  // the page the browser extension asked for (safebrowse://history ...): { page, acct, scan, hint, hasCode } or null.
  // The one-time login code stays in the main process; the page can only say "accept" or "drop".
  takePendingPage: () => ipcRenderer.invoke("app:take-pending-page"),
  acceptLink: () => ipcRenderer.invoke("app:accept-link"),
  dropLink: () => ipcRenderer.invoke("app:drop-link"),
  onOpenPage: (cb) => {
    const handler = () => cb();
    ipcRenderer.on("open-page", handler);
    return () => ipcRenderer.removeListener("open-page", handler);
  },
});
