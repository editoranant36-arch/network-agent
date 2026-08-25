const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const { spawn } = require("child_process");

let mainWindow = null;
let nextProcess = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 850,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: "#0b121d",
    title: "LAN Sentinel - Active Network Scanner",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  const isDev = process.env.NODE_ENV === "development" || !app.isPackaged;
  const startUrl = isDev ? "http://localhost:3000" : `http://localhost:${process.env.PORT || 3000}`;

  // If local server is not already started, start it
  mainWindow.loadURL(startUrl).catch(() => {
    // Retry loading if dev server is spinning up
    setTimeout(() => mainWindow.loadURL(startUrl), 1500);
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    if (nextProcess) nextProcess.kill();
    app.quit();
  }
});
