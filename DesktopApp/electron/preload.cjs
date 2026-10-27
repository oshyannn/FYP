"use strict";
// The ONLY things the web page can do: send an API request through the main process, and ask to restore a session.
// It never sees the login token or the sign-up secret.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("sb", {
  api: (method, path, body) => ipcRenderer.invoke("api", { method, path, body }),
  restoreSession: () => ipcRenderer.invoke("session:restore"),
});
