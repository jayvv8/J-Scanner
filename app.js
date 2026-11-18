
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

// CAMBIAR DISPOSITIVO

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
    scanStatus.textContent = "Esperando un archivo.";
    scanResults.replaceChildren();
  });
});

// ABRIR SELECTOR

uploadButton.addEventListener("click", () => {
  fileInput.click();
});

// VALIDAR ARCHIVO

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

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];

  if (!file) return;

  const extension = getExtension(file.name);

  if (!extension) {
    selectedFile = null;
    fileInput.value = "";

    fileName.textContent = "Formato no admitido.";
    scanStatus.textContent = "No se ha cargado ningún archivo válido.";

    return;
  }

  selectedFile = file;

  fileName.textContent =
    file.name + " · " + formatSize(file.size);

  scanStatus.textContent =
    "Archivo seleccionado. Motor de análisis pendiente.";

  scanResults.replaceChildren();
});

// INICIAR DEMOSTRACIÓN DE ANÁLISIS

function showMessage(message) {
  scanResults.replaceChildren();

  const paragraph = document.createElement("p");
  paragraph.textContent = message;

  scanResults.appendChild(paragraph);
}

// INICIAR SESIÓN

loginButton.addEventListener("click", () => {
  alert("El sistema de cuentas estará disponible en una próxima etapa.");
});

// PREMIUM

premiumButton.addEventListener("click", () => {
  alert("El sistema de suscripciones Premium estará disponible próximamente.");
});

// ESTADO INICIAL

scanStatus.textContent =
  "J-Scanner está preparado para recibir un archivo.";

showMessage(
  "Selecciona un informe compatible para comenzar."
);
