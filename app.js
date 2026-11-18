
"use strict";

// ========================================
// J-SCANNER
// SISTEMA PRINCIPAL
// VERSION 1.3
// ========================================

const APP_VERSION = "1.3";

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
// CONFIGURACION DE DISPOSITIVOS
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
// CREAR BOTON DE ANALISIS
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

function createElement(tag, text, parent) {
  const element = document.createElement(tag);

  if (text !== undefined && text !== null) {
    element.textContent = String(text);
  }

  if (parent) {
    parent.appendChild(element);
  }

  return element;
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
// VERSION REAL DEL MOTOR
// ========================================

function getEngineVersion(result) {
  const engineVersion = window.JScannerIPhone?.version;

  if (engineVersion) {
    return String(engineVersion);
  }

  if (result && result.version) {
    return String(result.version);
  }

  return "No disponible";
}

// ========================================
// LIMPIAR EVIDENCIAS ILEGIBLES
// ========================================

function cleanEvidenceText(value) {
  if (typeof value !== "string") {
    return "";
  }

  const cleaned = value
    .replace(/\uFFFD/g, "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/[^\x20-\x7E\u00A0-\u024F\u1E00-\u1EFF]/g, "");

  const usefulCharacters = cleaned.replace(/[\s]/g, "").length;

  if (usefulCharacters < 8) {
    return "";
  }

  const readableCharacters = cleaned.match(/[a-zA-Z0-9áéíóúÁÉÍÓÚñÑ/_.:-]/g) || [];

  const readability = readableCharacters.length / usefulCharacters;

  if (readability < 0.65) {
    return "";
  }

  return cleaned.trim();
}

// ========================================
// COLORES DE RIESGO
// ========================================

function getRiskInfo(severity) {
  switch (severity) {
    case "high":
      return {
        label: "RIESGO ALTO",
        color: "#ff6464",
        description: "Indicador fuerte que necesita comprobación."
      };

    case "medium":
      return {
        label: "RIESGO MEDIO",
        color: "#ffc15c",
        description: "Indicador contextual que requiere revisión."
      };

    default:
      return {
        label: "RIESGO BAJO",
        color: "#65baff",
        description: "Referencia informativa sin confirmación."
      };
  }
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
// MOSTRAR EVIDENCIAS
// ========================================

function renderEvidence(finding, parent) {
  const evidenceList = Array.isArray(finding.evidence)
    ? finding.evidence
    : [];

  const evidenceTitle = createElement(
    "h4",
    "EVIDENCIAS ENCONTRADAS",
    parent
  );

  evidenceTitle.style.marginTop = "16px";

  const readableEvidence = evidenceList
    .map(evidence => ({
      ...evidence,
      readableText: cleanEvidenceText(evidence.text || "")
    }))
    .filter(evidence => evidence.readableText.length > 0);

  if (readableEvidence.length === 0) {
    createElement(
      "p",
      "Los fragmentos disponibles no contienen texto suficientemente legible para mostrarse. Se requiere revisar el archivo original.",
      parent
    );

    return;
  }

  readableEvidence.forEach((evidence, index) => {
    const evidenceBox = document.createElement("div");

    evidenceBox.style.background = "rgba(0,0,0,0.22)";
    evidenceBox.style.padding = "10px";
    evidenceBox.style.marginTop = "8px";
    evidenceBox.style.borderRadius = "8px";
    evidenceBox.style.overflowWrap = "anywhere";

    createElement(
      "strong",
      "Fragmento " + (index + 1),
      evidenceBox
    );

    if (evidence.line !== undefined) {
      createElement(
        "p",
        "Línea: " + evidence.line,
        evidenceBox
      );
    }

    const excerpt = createElement(
      "p",
      evidence.readableText,
      evidenceBox
    );

    excerpt.style.fontSize = "13px";
    excerpt.style.whiteSpace = "pre-wrap";
    excerpt.style.overflowWrap = "anywhere";

    parent.appendChild(evidenceBox);
  });
}

// ========================================
// TARJETA DE CADA HALLAZGO
// ========================================

function renderFinding(finding, index) {
  const item = document.createElement("div");

  item.style.padding = "16px";
  item.style.marginTop = "14px";
  item.style.borderRadius = "12px";
  item.style.background = "rgba(255,255,255,0.06)";
  item.style.border = "1px solid rgba(255,255,255,0.09)";
  item.style.overflowWrap = "anywhere";

  const risk = getRiskInfo(finding.severity);

  const heading = createElement(
    "h3",
    (index + 1) + ". " + (finding.name || "Indicador sin nombre"),
    item
  );

  heading.style.marginBottom = "12px";

  const riskLabel = createElement(
    "strong",
    risk.label,
    item
  );

  riskLabel.style.color = risk.color;
  riskLabel.style.display = "block";
  riskLabel.style.marginBottom = "8px";

  createElement(
    "p",
    "Categoría: " + (finding.category || "No especificada"),
    item
  );

  createElement(
    "p",
    "Clasificación: " + (finding.confidence || "No especificada"),
    item
  );

  createElement(
    "p",
    risk.description,
    item
  );

  createElement(
    "p",
    "Archivo: " + (finding.file || "No especificado"),
    item
  );

  createElement(
    "p",
    "Fragmentos de evidencia mostrados: " +
      (Array.isArray(finding.evidence)
        ? finding.evidence.length
        : 0),
    item
  );

  const explanation = document.createElement("div");

  explanation.style.marginTop = "12px";
  explanation.style.padding = "10px";
  explanation.style.background = "rgba(0,0,0,0.18)";
  explanation.style.borderRadius = "8px";

  createElement(
    "strong",
    "¿Por qué aparece este resultado?",
    explanation
  );

  createElement(
    "p",
    finding.explanation || "No hay explicación disponible.",
    explanation
  );

  item.appendChild(explanation);

  renderEvidence(finding, item);

  return item;
}

// ========================================
// MOSTRAR INFORME COMPLETO
// ========================================

function renderResults(result) {
  scanResults.replaceChildren();

  const heading = createElement(
    "h2",
    "INFORME DE J-SCANNER",
    scanResults
  );

  heading.style.marginBottom = "16px";

  createElement(
    "p",
    "Motor: " + (result.engine || "J-SCANNER IPHONE"),
    scanResults
  );

  createElement(
    "p",
    "Versión: " + getEngineVersion(result),
    scanResults
  );

  createElement(
    "p",
    "Archivo: " + (result.fileName || "No especificado"),
    scanResults
  );

  createElement(
    "p",
    "Archivos examinados: " + (result.scannedFiles ?? 0),
    scanResults
  );

  createElement(
    "p",
    "Entradas TAR procesadas: " + (result.entriesProcessed ?? "No disponible"),
    scanResults
  );

  createElement(
    "p",
    "Hallazgos distintos: " +
      (Array.isArray(result.findings)
        ? result.findings.length
        : 0),
    scanResults
  );

  const findings = Array.isArray(result.findings)
    ? result.findings
    : [];

  const highCount = findings.filter(
    item => item.severity === "high"
  ).length;

  const mediumCount = findings.filter(
    item => item.severity === "medium"
  ).length;

  const lowCount = findings.filter(
    item => item.severity !== "high" &&
      item.severity !== "medium"
  ).length;

  const summary = document.createElement("div");

  summary.style.padding = "14px";
  summary.style.marginTop = "16px";
  summary.style.borderRadius = "10px";
  summary.style.background = "rgba(255,255,255,0.06)";

  createElement("h3", "RESUMEN DE RIESGOS", summary);

  const high = createElement(
    "p",
    "Riesgo alto: " + highCount,
    summary
  );
  high.style.color = "#ff6464";

  const medium = createElement(
    "p",
    "Riesgo medio: " + mediumCount,
    summary
  );
  medium.style.color = "#ffc15c";

  const low = createElement(
    "p",
    "Riesgo bajo o informativo: " + lowCount,
    summary
  );
  low.style.color = "#65baff";

  scanResults.appendChild(summary);

  // ======================================
  // ESTADO DEL ANALISIS
  // ======================================

  const statusBox = document.createElement("div");

  statusBox.style.padding = "14px";
  statusBox.style.marginTop = "14px";
  statusBox.style.borderRadius = "10px";
  statusBox.style.background = "rgba(56,232,165,0.08)";

  if (result.status === "NO_INDICATORS_FOUND") {
    createElement(
      "strong",
      "No se encontraron indicadores conocidos.",
      statusBox
    );

    createElement(
      "p",
      "Esto no garantiza que el dispositivo o el juego estén libres de modificaciones.",
      statusBox
    );

  } else {
    createElement(
      "strong",
      "Se encontraron indicadores que requieren revisión.",
      statusBox
    );

    createElement(
      "p",
      "Los hallazgos son señales técnicas y no demuestran por sí solos el uso de hacks.",
      statusBox
    );
  }

  scanResults.appendChild(statusBox);

  // ======================================
  // ARCHIVO PARCIALMENTE ANALIZADO
  // ======================================

  if (result.truncated) {
    const warning = document.createElement("div");

    warning.style.padding = "12px";
    warning.style.marginTop = "14px";
    warning.style.borderRadius = "10px";
    warning.style.background = "rgba(255,193,92,0.12)";
    warning.style.border = "1px solid #ffc15c";

    createElement(
      "strong",
      "ADVERTENCIA: ANÁLISIS PARCIAL",
      warning
    );

    createElement(
      "p",
      "Se alcanzó un límite de análisis. Algunos archivos podrían no haberse examinado. No se debe interpretar este informe como un análisis completo.",
      warning
    );

    scanResults.appendChild(warning);
  }

  // ======================================
  // DETALLES DE LOS HALLAZGOS
  // ======================================

  if (findings.length > 0) {
    createElement(
      "h3",
      "DETALLES Y EVIDENCIAS",
      scanResults
    );

    findings.forEach((finding, index) => {
      scanResults.appendChild(
        renderFinding(finding, index)
      );
    });

  } else {
    createElement(
      "p",
      "No hay hallazgos que mostrar con las reglas actuales.",
      scanResults
    );
  }

  // ======================================
  // ADVERTENCIA FINAL
  // ======================================

  const disclaimer = document.createElement("div");

  disclaimer.style.marginTop = "20px";
  disclaimer.style.padding = "14px";
  disclaimer.style.borderRadius = "10px";
  disclaimer.style.background = "rgba(255,255,255,0.05)";
  disclaimer.style.fontSize = "13px";
  disclaimer.style.lineHeight = "1.6";

  createElement(
    "strong",
    "LIMITACIONES DEL ANALISIS",
    disclaimer
  );

  createElement(
    "p",
    result.disclaimer ||
      "Este análisis identifica indicadores técnicos. No confirma por sí solo el uso de hacks ni modificaciones de juegos.",
    disclaimer
  );

  scanResults.appendChild(disclaimer);
}

// ========================================
// INICIAR ANALISIS IPHONE
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
// INICIAR SESION
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
