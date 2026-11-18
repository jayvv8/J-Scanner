
/*
========================================
 J-SCANNER
 IPHONE DIAGNOSTIC ENGINE
 VERSION 1.3
 BINARY FILTER + FALSE POSITIVE CONTROL
========================================
*/

(function () {
  "use strict";

  const MAX_DECOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024;
  const MAX_ORIGINAL_SIZE = 1024 * 1024 * 1024;
  const MAX_TEXT_FILE_SIZE = 2 * 1024 * 1024;
  const MAX_TOTAL_TEXT_SIZE = 80 * 1024 * 1024;
  const MAX_ENTRIES = 50000;
  const MAX_INSPECTED_FILES = 10000;
  const MAX_EVIDENCE_PER_RULE = 4;

  const TEXT_EXTENSIONS = [
    ".txt",
    ".log",
    ".plist",
    ".json",
    ".xml",
    ".ips",
    ".crash",
    ".panic",
    ".csv"
  ];

  // ======================================
  // RUTAS LEGITIMAS QUE NO SON INDICADORES
  // ======================================

  const SAFE_PATHS = [
    "/System/Library/PreferenceBundles/",
    "/System/Library/Frameworks/",
    "/System/Library/PrivateFrameworks/",
    "/System/Library/LaunchDaemons/",
    "/System/Library/LaunchAgents/",
    "/System/Applications/",
    "/usr/lib/system/",
    "/usr/lib/dyld"
  ];

  // ======================================
  // REGLAS DE DETECCION
  // ======================================

  const RULES = [
    {
      id: "frida_artifact",
      name: "Artefacto específico de Frida",
      category: "Instrumentación",
      severity: "high",
      confidence: "Indicador fuerte",

      explanation:
        "Se encontró una referencia específica a un componente de Frida. Debe verificarse si corresponde a una herramienta activa, un registro histórico o una referencia de diagnóstico.",

      validate: function (line) {
        return /\bfrida-(?:server|gadget|agent)\b/i.test(line) ||
          (
            /\bfrida\b/i.test(line) &&
            /\b(?:27042|27043|gadget|server|agent|attach|spawn)\b/i.test(line)
          );
      }
    },

    {
      id: "dyld_injection",
      name: "Variable de carga dinámica",
      category: "Carga de bibliotecas",
      severity: "high",
      confidence: "Indicador fuerte",

      explanation:
        "Se encontró una asignación de DYLD_INSERT_LIBRARIES con una ruta. La presencia de esta variable no demuestra por sí sola que una biblioteca haya sido cargada.",

      validate: function (line) {
        return /DYLD_INSERT_LIBRARIES\s*=\s*["']?\/[^;\s"']+/i.test(line);
      }
    },

    {
      id: "jailbreak_paths",
      name: "Ruta asociada a jailbreak",
      category: "Sistema",
      severity: "medium",
      confidence: "Indicador contextual",

      explanation:
        "Se encontró una ruta específica habitualmente asociada a herramientas de modificación de iOS. Debe verificarse su existencia, actividad y relación con el proceso.",

      validate: function (line) {
        return /\/(?:Applications\/(?:Cydia|Sileo|Zebra)\.app|Library\/MobileSubstrate(?:\/|$)|Library\/TweakInject(?:\/|$)|usr\/lib\/TweakInject(?:\/|$)|var\/jb(?:\/|$)|var\/containers\/Bundle\/tweaksupport(?:\/|$))/i.test(line);
      }
    },

    {
      id: "injection_framework",
      name: "Framework de modificación",
      category: "Bibliotecas",
      severity: "medium",
      confidence: "Indicador contextual",

      explanation:
        "Se encontró una referencia a un framework relacionado con instrumentación o modificación de procesos, acompañada de un contexto de carga.",

      validate: function (line) {
        return /\b(?:MobileSubstrate|Substitute|ElleKit|libhooker)\b/i.test(line) &&
          /\b(?:loaded|loading|injected|injection|dylib|mapped|process)\b/i.test(line);
      }
    },

    {
      id: "signature_failure",
      name: "Error de validación de firma",
      category: "Integridad",
      severity: "medium",
      confidence: "Indicador contextual",

      explanation:
        "Se encontró un error relacionado con la validación de una firma de código. También puede deberse a errores legítimos de instalación, desarrollo o actualización.",

      validate: function (line) {
        return /(?:code signature invalid|invalid code signature|signature validation failed)/i.test(line) &&
          /\b(?:amfi|codesign|executable|process|bundle|application)\b/i.test(line);
      }
    }
  ];

  // ======================================
  // UTILIDADES
  // ======================================

  function cleanPath(path) {
    return String(path)
      .replace(/\\/g, "/")
      .replace(/\0/g, "")
      .slice(0, 500);
  }

  function cleanEvidence(line) {
    return String(line)
      .replace(/\0/g, "")
      .replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]/g, "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 350);
  }

  function isSafePath(path) {
    const normalized = "/" + cleanPath(path).replace(/^\/+/, "");

    return SAFE_PATHS.some(function (safePath) {
      return normalized.startsWith(safePath);
    });
  }

  function hasTextExtension(path) {
    const name = cleanPath(path).toLowerCase();
    const basename = name.split("/").pop();

    return TEXT_EXTENSIONS.some(function (extension) {
      return basename.endsWith(extension);
    });
  }

  // ======================================
  // FILTRO DE CONTENIDO BINARIO
  // ======================================

  function isProbablyText(bytes) {
    if (!bytes || bytes.length === 0) {
      return false;
    }

    // Los archivos binarios de Apple pueden comenzar
    // con bplist00 aunque su extensión sea .plist.
    if (
      bytes.length >= 8 &&
      bytes[0] === 0x62 &&
      bytes[1] === 0x70 &&
      bytes[2] === 0x6c &&
      bytes[3] === 0x69 &&
      bytes[4] === 0x73 &&
      bytes[5] === 0x74
    ) {
      return false;
    }

    let printable = 0;
    let inspected = Math.min(bytes.length, 8192);

    for (let i = 0; i < inspected; i++) {
      const value = bytes[i];

      if (value === 0) {
        return false;
      }

      if (
        value === 9 ||
        value === 10 ||
        value === 13 ||
        (value >= 32 && value <= 126) ||
        value >= 160
      ) {
        printable++;
      }
    }

    return printable / inspected >= 0.85;
  }

  // ======================================
  // ANALISIS DE TEXTO
  // ======================================

  function analyzeText(text, filePath) {
    const findings = [];
    const lines = String(text).split(/\r?\n/);

    if (isSafePath(filePath)) {
      return findings;
    }

    for (const rule of RULES) {
      const evidence = [];
      const seen = new Set();

      for (let i = 0; i < lines.length; i++) {
        const originalLine = lines[i];

        if (!rule.validate(originalLine)) {
          continue;
        }

        const excerpt = cleanEvidence(originalLine);

        if (!excerpt || seen.has(excerpt)) {
          continue;
        }

        seen.add(excerpt);

        evidence.push({
          line: i + 1,
          text: excerpt
        });

        if (evidence.length >= MAX_EVIDENCE_PER_RULE) {
          break;
        }
      }

      if (evidence.length > 0) {
        findings.push({
          id: rule.id,
          name: rule.name,
          category: rule.category,
          severity: rule.severity,
          confidence: rule.confidence,
          explanation: rule.explanation,
          file: cleanPath(filePath),
          occurrences: evidence.length,
          evidence: evidence
        });
      }
    }

    return findings;
  }

  // ======================================
  // LECTOR PROGRESIVO
  // ======================================

  class StreamReader {
    constructor(stream, maxBytes) {
      this.reader = stream.getReader();
      this.maxBytes = maxBytes;
      this.chunks = [];
      this.firstOffset = 0;
      this.available = 0;
      this.totalRead = 0;
      this.done = false;
    }

    async fill(minimum) {
      while (this.available < minimum && !this.done) {
        const result = await this.reader.read();

        if (result.done) {
          this.done = true;
          break;
        }

        this.totalRead += result.value.byteLength;

        if (this.totalRead > this.maxBytes) {
          throw new Error(
            "El archivo descomprimido supera el límite de seguridad de 2 GB."
          );
        }

        this.chunks.push(result.value);
        this.available += result.value.byteLength;
      }
    }

    consume(length, destination) {
      let remaining = length;
      let written = 0;

      while (remaining > 0) {
        const chunk = this.chunks[0];

        const availableInChunk =
          chunk.byteLength - this.firstOffset;

        const amount = Math.min(
          remaining,
          availableInChunk
        );

        if (destination) {
          destination.set(
            chunk.subarray(
              this.firstOffset,
              this.firstOffset + amount
            ),
            written
          );
        }

        this.firstOffset += amount;
        this.available -= amount;
        remaining -= amount;
        written += amount;

        if (this.firstOffset >= chunk.byteLength) {
          this.chunks.shift();
          this.firstOffset = 0;
        }
      }
    }

    async readExact(length) {
      if (length === 0) {
        return new Uint8Array(0);
      }

      await this.fill(length);

      if (this.available < length) {
        if (this.available === 0) {
          return null;
        }

        throw new Error(
          "El archivo TAR está incompleto o dañado."
        );
      }

      const output = new Uint8Array(length);
      this.consume(length, output);

      return output;
    }

    async skip(length) {
      let remaining = length;

      while (remaining > 0) {
        if (this.available === 0) {
          await this.fill(1);
        }

        if (this.available === 0) {
          throw new Error(
            "El archivo TAR terminó antes de tiempo."
          );
        }

        const amount = Math.min(
          remaining,
          this.available
        );

        this.consume(amount, null);
        remaining -= amount;
      }
    }

    async cancel() {
      try {
        await this.reader.cancel();
      } catch {
        // Flujo cerrado.
      }
    }
  }

  // ======================================
  // LECTOR DE TAMAÑO TAR
  // ======================================

  function parseTarSize(bytes) {
    if (bytes[0] & 0x80) {
      let value = 0;

      for (let i = 0; i < bytes.length; i++) {
        const byte = i === 0
          ? bytes[i] & 0x7f
          : bytes[i];

        value = value * 256 + byte;

        if (!Number.isSafeInteger(value)) {
          throw new Error("Tamaño TAR no compatible.");
        }
      }

      return value;
    }

    const text = new TextDecoder()
      .decode(bytes)
      .replace(/\0.*$/, "")
      .trim();

    if (!text) return 0;

    const value = parseInt(text, 8);

    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("Tamaño TAR inválido.");
    }

    return value;
  }

  // ======================================
  // ANALISIS TAR.GZ
  // ======================================

  async function analyzeTarStream(stream) {
    const source = new StreamReader(
      stream,
      MAX_DECOMPRESSED_SIZE
    );

    const findings = [];
    const inspected = [];

    let totalTextSize = 0;
    let entries = 0;
    let skippedBinary = 0;
    let skippedUnsupported = 0;
    let truncated = false;

    try {
      while (entries < MAX_ENTRIES) {
        const header = await source.readExact(512);

        if (!header) break;

        if (header.every(byte => byte === 0)) {
          break;
        }

        entries++;

        const decoder = new TextDecoder();

        const name = decoder.decode(
          header.subarray(0, 100)
        ).replace(/\0.*$/, "");

        const prefix = decoder.decode(
          header.subarray(345, 500)
        ).replace(/\0.*$/, "");

        const path = prefix
          ? prefix + "/" + name
          : name;

        const size = parseTarSize(
          header.subarray(124, 136)
        );

        const type = String.fromCharCode(
          header[156] || 0
        );

        const regularFile =
          type === "\0" || type === "0";

        const padding = (512 - (size % 512)) % 512;

        const eligible =
          regularFile &&
          hasTextExtension(path) &&
          !isSafePath(path) &&
          size > 0 &&
          size <= MAX_TEXT_FILE_SIZE;

        const withinTotalLimit =
          totalTextSize + size <= MAX_TOTAL_TEXT_SIZE;

        const withinFileLimit =
          inspected.length < MAX_INSPECTED_FILES;

        const canInspect =
          eligible &&
          withinTotalLimit &&
          withinFileLimit;

        if (canInspect) {
          const data = await source.readExact(size);

          if (!data) {
            throw new Error(
              "No se pudo leer un archivo interno del TAR."
            );
          }

          if (!isProbablyText(data)) {
            skippedBinary++;
          } else {
            totalTextSize += data.byteLength;

            const text = new TextDecoder(
              "utf-8",
              { fatal: false }
            ).decode(data);

            inspected.push(cleanPath(path));

            findings.push(
              ...analyzeText(text, path)
            );
          }
        } else {
          if (eligible && !withinTotalLimit) {
            truncated = true;
          }

          if (eligible && !withinFileLimit) {
            truncated = true;
          }

          if (!eligible) {
            skippedUnsupported++;
          }

          await source.skip(size);
        }

        if (padding > 0) {
          await source.skip(padding);
        }

        if (!withinFileLimit) {
          truncated = true;
          break;
        }
      }

      if (entries >= MAX_ENTRIES) {
        truncated = true;
      }

      return {
        inspected,
        findings,
        totalSize: totalTextSize,
        entries,
        skippedBinary,
        skippedUnsupported,
        truncated
      };

    } finally {
      await source.cancel();
    }
  }

  // ======================================
  // ANALISIS ZIP
  // ======================================

  async function analyzeZip(file) {
    if (!window.JSZip) {
      throw new Error("No se encontró JSZip.");
    }

    const archive = await window.JSZip.loadAsync(file);

    const findings = [];
    const inspected = [];

    let totalSize = 0;
    let entries = 0;
    let skippedBinary = 0;
    let skippedUnsupported = 0;
    let truncated = false;

    for (const [path, entry] of Object.entries(archive.files)) {
      entries++;

      if (entry.dir) continue;

      if (
        !hasTextExtension(path) ||
        isSafePath(path)
      ) {
        skippedUnsupported++;
        continue;
      }

      if (inspected.length >= MAX_INSPECTED_FILES) {
        truncated = true;
        break;
      }

      if (
        entry._data &&
        entry._data.uncompressedSize > MAX_TEXT_FILE_SIZE
      ) {
        skippedUnsupported++;
        continue;
      }

      const data = await entry.async("uint8array");

      if (data.byteLength > MAX_TEXT_FILE_SIZE) {
        skippedUnsupported++;
        continue;
      }

      if (!isProbablyText(data)) {
        skippedBinary++;
        continue;
      }

      if (totalSize + data.byteLength > MAX_TOTAL_TEXT_SIZE) {
        truncated = true;
        break;
      }

      totalSize += data.byteLength;

      const text = new TextDecoder(
        "utf-8",
        { fatal: false }
      ).decode(data);

      inspected.push(cleanPath(path));

      findings.push(
        ...analyzeText(text, path)
      );
    }

    return {
      inspected,
      findings,
      totalSize,
      entries,
      skippedBinary,
      skippedUnsupported,
      truncated
    };
  }

  // ======================================
  // DESCOMPRESION GZIP
  // ======================================

  async function analyzeGzip(file) {
    if (typeof DecompressionStream === "undefined") {
      throw new Error(
        "Este navegador no permite descomprimir GZIP."
      );
    }

    const stream = file.stream().pipeThrough(
      new DecompressionStream("gzip")
    );

    return await analyzeTarStream(stream);
  }

  // ======================================
  // FUNCION PRINCIPAL
  // ======================================

  async function scan(file) {
    if (!(file instanceof File)) {
      throw new Error("Archivo inválido.");
    }

    if (file.size > MAX_ORIGINAL_SIZE) {
      throw new Error(
        "El archivo original supera el límite de 1 GB."
      );
    }

    const name = file.name.toLowerCase();
    let result;

    if (name.endsWith(".zip")) {
      result = await analyzeZip(file);

    } else if (
      name.endsWith(".tar.gz") ||
      name.endsWith(".tgz") ||
      name.endsWith(".gz")
    ) {
      result = await analyzeGzip(file);

    } else {
      throw new Error("Formato no compatible.");
    }

    const highCount = result.findings.filter(
      item => item.severity === "high"
    ).length;

    const mediumCount = result.findings.filter(
      item => item.severity === "medium"
    ).length;

    const categories = [
      ...new Set(
        result.findings.map(item => item.category)
      )
    ];

    return {
      engine: "J-SCANNER IPHONE",
      version: "1.3",

      fileName: file.name,
      fileSize: file.size,

      scannedFiles: result.inspected.length,
      findings: result.findings,
      categories: categories,

      highRiskCount: highCount,
      mediumRiskCount: mediumCount,

      entriesProcessed: result.entries,
      skippedBinary: result.skippedBinary,
      skippedUnsupported: result.skippedUnsupported,

      truncated: result.truncated,

      status: result.findings.length
        ? "REVIEW_REQUIRED"
        : "NO_INDICATORS_FOUND",

      disclaimer:
        "J-Scanner 1.3 filtra archivos binarios y rutas conocidas del sistema iOS. Los indicadores son referencias técnicas que requieren revisión manual. No demuestran por sí solos el uso de hacks ni modificaciones de Free Fire. El análisis no accede a los datos privados del juego ni verifica directamente su integridad. Puede haber falsos positivos y falsos negativos."
    };
  }

  // ======================================
  // EXPORTAR MOTOR
  // ======================================

  window.JScannerIPhone = {
    scan: scan,
    version: "1.3"
  };

})();
