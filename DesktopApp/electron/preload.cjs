"use strict";
// The ONLY things the web page can do: send an API request through the main process, and ask to restore a session.
// It never sees the login token or the sign-up secret.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("sb", {
  api: (method, path, body) => ipcRenderer.invoke("api", { method, path, body }),
  restoreSession: () => ipcRenderer.invoke("session:restore"),
  // pages the browser extension asked for (safebrowse://history ...); only { page: <fixed page name>, acct: <hash or null> } ever arrives
  takePendingPage: () => ipcRenderer.invoke("app:take-pending-page"),
  onOpenPage: (cb) => {
    const handler = (_event, req) => cb(req);
    ipcRenderer.on("open-page", handler);
    return () => ipcRenderer.removeListener("open-page", handler);
  },
});
