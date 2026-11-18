
"use strict";

// ========================================
// J-SCANNER
// SISTEMA PRINCIPAL
// ========================================

const deviceCards = document.querySelectorAll(".device-card");
const fileInput = document.getElementById("fileInput");
const uploadButton = document.getElementById("uploadButton");
const uploadTitle = document.getElementById("uploadTitle");
const uploadDescription = document.getElementById("uploadDescription");
const fileName = document.getElementById("fileName");
const scanStatus = document.getElementById("scanStatus");
const scanResults = document.getElementById("scanResults");

const loginButton = document.getElementById("loginButton");
const premiumButton = document.getElementById("premiumButton");

let selectedDevice = "iphone";
let selectedFile = null;
let isScanning = false;

// ========================================
// CONFIGURACIÓN DE DISPOSITIVOS
// ========================================

const deviceConfig = {
  iphone: {
    title: "Cargar Sysdiagnose",
    description: "Selecciona el archivo de diagnóstico de tu iPhone.",
    extensions: [".tar.gz", ".tgz", ".zip", ".gz"],
    accept: ".tar.gz,.tgz,.zip,.gz"
  },

  android: {
    title: "Cargar Bug Report",
    description: "Selecciona un informe de diagnóstico Android.",
    extensions: [".zip", ".txt", ".gz"],
    accept: ".zip,.txt,.gz"
  }
};

// ========================================
// CREAR BOTÓN DE ANÁLISIS
// ========================================

const scanButton = document.createElement("button");

scanButton.type = "button";
scanButton.id = "startScanButton";
scanButton.textContent = "ANALIZAR ARCHIVO";
scanButton.disabled = true;

scanButton.style.display = "block";
scanButton.style.width = "100%";
scanButton.style.marginTop = "15px";
scanButton.style.padding = "14px";
scanButton.style.border = "none";
scanButton.style.borderRadius = "10px";
scanButton.style.background = "#38e8a5";
scanButton.style.color = "#07110d";
scanButton.style.fontWeight = "bold";
scanButton.style.fontSize = "15px";
scanButton.style.cursor = "pointer";
scanButton.style.opacity = "0.5";

uploadButton.insertAdjacentElement("afterend", scanButton);

// ========================================
// FUNCIONES GENERALES
// ========================================

function showMessage(message) {
  scanResults.replaceChildren();

  const paragraph = document.createElement("p");
  paragraph.textContent = message;

  scanResults.appendChild(paragraph);
}

function getExtension(filename) {
  const lower = filename.toLowerCase();

  return deviceConfig[selectedDevice].extensions.find(ext =>
    lower.endsWith(ext)
  ) || "";
}

function formatSize(bytes) {
  if (bytes < 1024 * 1024) {
    return (bytes / 1024).toFixed(2) + " KB";
  }

  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

function updateScanButton() {
  const available =
    selectedDevice === "iphone" &&
    selectedFile !== null &&
    !isScanning;

  scanButton.disabled = !available;
  scanButton.style.opacity = available ? "1" : "0.5";
}

// ========================================
// CAMBIAR DISPOSITIVO
// ========================================

deviceCards.forEach(card => {
  card.addEventListener("click", () => {
    selectedDevice = card.dataset.device;

    deviceCards.forEach(item => {
      item.classList.remove("active");
    });

    card.classList.add("active");

    const config = deviceConfig[selectedDevice];

    uploadTitle.textContent = config.title;
    uploadDescription.textContent = config.description;
    fileInput.accept = config.accept;

    selectedFile = null;
    fileInput.value = "";

    fileName.textContent = "Ningún archivo seleccionado";

    scanStatus.textContent =
      selectedDevice === "iphone"
        ? "Esperando un archivo."
        : "Motor Android pendiente de desarrollo.";

    scanButton.textContent = "ANALIZAR ARCHIVO";

    showMessage(
      selectedDevice === "iphone"
        ? "Selecciona un Sysdiagnose compatible para comenzar."
        : "El motor Android todavía no está disponible."
    );

    updateScanButton();
  });
});

// ========================================
// ABRIR SELECTOR DE ARCHIVOS
// ========================================

uploadButton.addEventListener("click", () => {
  fileInput.click();
});

// ========================================
// VALIDAR ARCHIVO
// ========================================

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];

  if (!file) return;

  const extension = getExtension(file.name);

  if (!extension) {
    selectedFile = null;
    fileInput.value = "";

    fileName.textContent = "Formato no admitido.";
    scanStatus.textContent = "Selecciona un archivo compatible.";

    updateScanButton();
    showMessage("El formato seleccionado no está permitido.");

    return;
  }

  selectedFile = file;

  fileName.textContent =
    file.name + " · " + formatSize(file.size);

  if (selectedDevice === "iphone") {
    scanStatus.textContent =
      "Archivo seleccionado. Listo para analizar.";

    showMessage(
      "Archivo preparado. Pulsa ANALIZAR ARCHIVO para comenzar."
    );
  } else {
    scanStatus.textContent =
      "Archivo seleccionado. Motor Android pendiente.";

    showMessage(
      "La carga funciona, pero el análisis Android todavía no está implementado."
    );
  }

  updateScanButton();
});

// ========================================
// MOSTRAR RESULTADOS
// ========================================

function renderResults(result) {
  scanResults.replaceChildren();

  const heading = document.createElement("h3");

  heading.textContent = "INFORME DE J-SCANNER";

  scanResults.appendChild(heading);

  const summary = document.createElement("p");

  summary.textContent =
    "Archivos examinados: " + result.scannedFiles;

  scanResults.appendChild(summary);

  const fileInfo = document.createElement("p");

  fileInfo.textContent =
    "Archivo: " + result.fileName;

  scanResults.appendChild(fileInfo);

  const status = document.createElement("p");

  if (result.status === "NO_INDICATORS_FOUND") {
    status.textContent =
      "RESULTADO: No se encontraron indicadores conocidos.";

  } else {
    status.textContent =
      "RESULTADO: Se encontraron indicadores que requieren revisión.";
  }

  scanResults.appendChild(status);

  const count = document.createElement("p");

  count.textContent =
    "Indicadores encontrados: " + result.findings.length;

  scanResults.appendChild(count);

  if (result.findings.length > 0) {
    const findingsTitle = document.createElement("h4");

    findingsTitle.textContent = "DETALLES";

    scanResults.appendChild(findingsTitle);

    result.findings.forEach((finding, index) => {
      const item = document.createElement("div");

      item.style.padding = "12px";
      item.style.marginTop = "10px";
      item.style.borderRadius = "8px";
      item.style.background = "rgba(255,255,255,0.06)";

      const name = document.createElement("strong");

      name.textContent =
        (index + 1) + ". " + finding.name;

      const category = document.createElement("p");

      category.textContent =
        "Categoría: " + finding.category;

      const occurrences = document.createElement("p");

      occurrences.textContent =
        "Coincidencias: " + finding.occurrences;

      const path = document.createElement("p");

      path.textContent =
        "Archivo: " + finding.file;

      const confidence = document.createElement("p");

      confidence.textContent =
        finding.confidence;

      item.append(
        name,
        category,
        occurrences,
        path,
        confidence
      );

      scanResults.appendChild(item);
    });
  }

  const disclaimer = document.createElement("p");

  disclaimer.style.marginTop = "18px";
  disclaimer.style.fontSize = "13px";
  disclaimer.textContent = result.disclaimer;

  scanResults.appendChild(disclaimer);
}

// ========================================
// INICIAR ANÁLISIS IPHONE
// ========================================

async function startScan() {
  if (isScanning || !selectedFile) return;

  if (selectedDevice !== "iphone") {
    showMessage("El motor Android todavía no está disponible.");
    return;
  }

  if (!window.JScannerIPhone) {
    scanStatus.textContent = "Error al cargar el motor.";

    showMessage(
      "No se encontró el motor iPhone. Comprueba los scripts de index.html."
    );

    return;
  }

  if (!window.JSZip) {
    scanStatus.textContent = "Error al cargar JSZip.";

    showMessage(
      "No se pudo cargar la biblioteca necesaria para analizar archivos ZIP."
    );

    return;
  }

  isScanning = true;
  updateScanButton();

  scanButton.textContent = "ANALIZANDO...";

  scanStatus.textContent =
    "J-Scanner está examinando el archivo. Espera...";

  showMessage(
    "Análisis en progreso. No cierres esta página."
  );

  try {
    const result = await window.JScannerIPhone.scan(selectedFile);

    renderResults(result);

    scanStatus.textContent =
      "Análisis finalizado correctamente.";

  } catch (error) {
    console.error("J-Scanner:", error);

    scanStatus.textContent =
      "No se pudo completar el análisis.";

    showMessage(
      "Error durante el análisis: " +
      (error.message || "Error desconocido.")
    );

  } finally {
    isScanning = false;

    scanButton.textContent = "ANALIZAR ARCHIVO";

    updateScanButton();
  }
}

scanButton.addEventListener("click", startScan);

// ========================================
// INICIAR SESIÓN
// ========================================

loginButton.addEventListener("click", () => {
  alert(
    "El sistema de cuentas estará disponible en una próxima etapa."
  );
});

// ========================================
// PREMIUM
// ========================================

premiumButton.addEventListener("click", () => {
  alert(
    "El sistema de suscripciones Premium estará disponible próximamente."
  );
});

// ========================================
// ESTADO INICIAL
// ========================================

scanStatus.textContent =
  "J-Scanner está preparado para recibir un archivo.";

showMessage(
  "Selecciona un informe compatible para comenzar."
);

updateScanButton();
