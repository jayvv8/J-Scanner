
/*
========================================
 J-SCANNER
 IPHONE DIAGNOSTIC ENGINE
 Version 1.2
 EVIDENCE-BASED SCANNER
========================================
*/

(function () {
  "use strict";

  // ======================================
  // LIMITES DE SEGURIDAD
  // ======================================

  const MAX_FILE_SIZE = 2 * 1024 * 1024;
  const MAX_TOTAL_TEXT_SIZE = 80 * 1024 * 1024;
  const MAX_DECOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024;
  const MAX_ORIGINAL_SIZE = 1024 * 1024 * 1024;
  const MAX_ENTRIES = 50000;
  const MAX_INSPECTED_FILES = 10000;
  const MAX_EVIDENCE_PER_RULE = 4;

  const TEXT_EXTENSIONS = [
    ".txt", ".log", ".plist", ".json",
    ".xml", ".ips", ".crash", ".panic", ".csv"
  ];

  // ======================================
  // REGLAS DE DETECCION
  // No se consideran pruebas de trampas.
  // ======================================

  const RULES = [
    {
      id: "frida_artifact",
      name: "Artefacto de Frida",
      category: "Instrumentación",
      severity: "high",
      confidence: "Indicador fuerte",
      explanation:
        "Se encontró una referencia específica a un componente de Frida. Debe comprobarse si corresponde a una herramienta activa o a un registro histórico.",
      pattern:
        /\bfrida(?:-server|-gadget|-agent)?\b/i,
      validate: function (line) {
        return /\b(frida-server|frida-gadget|frida-agent)\b/i.test(line) ||
          (/\bfrida\b/i.test(line) &&
           /\b(27042|27043|gadget|server|agent|attach|spawn)\b/i.test(line));
      }
    },
    {
      id: "dyld_injection",
      name: "Variable de carga dinámica",
      category: "Carga de bibliotecas",
      severity: "high",
      confidence: "Indicador fuerte",
      explanation:
        "Se encontró una asignación de DYLD_INSERT_LIBRARIES con una ruta. La referencia por sí sola no demuestra que una biblioteca haya sido cargada.",
      pattern:
        /\bDYLD_INSERT_LIBRARIES\b/i,
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
        "Se encontró una ruta habitualmente asociada a entornos modificados de iOS. Hay que verificar si está activa y a qué proceso pertenece.",
      pattern:
        /\/(?:Applications\/Cydia\.app|Library\/MobileSubstrate|var\/jb|usr\/lib\/TweakInject|Library\/PreferenceBundles)/i,
      validate: function (line) {
        return /\/(?:Applications\/Cydia\.app|Library\/MobileSubstrate|var\/jb|usr\/lib\/TweakInject|Library\/PreferenceBundles)/i.test(line);
      }
    },
    {
      id: "injection_framework",
      name: "Framework de modificación",
      category: "Bibliotecas",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation:
        "Se encontró una referencia a un framework utilizado para modificar o instrumentar procesos. Puede aparecer en registros sin que exista una modificación activa.",
      pattern:
        /\b(?:MobileSubstrate|Substrate|Substitute|ElleKit|libhooker)\b/i,
      validate: function (line) {
        return /\b(?:MobileSubstrate|Substrate|Substitute|ElleKit|libhooker)\b/i.test(line) &&
          /\b(load|loaded|loading|injected|injection|dylib|library|image|process|mapped)\b/i.test(line);
      }
    },
    {
      id: "signature_failure",
      name: "Error de firma de código",
      category: "Integridad de aplicaciones",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation:
        "Se encontró un mensaje relacionado con una firma de código inválida. Puede deberse a errores legítimos de instalación, desarrollo o actualización.",
      pattern:
        /(?:code signature invalid|invalid code signature|signature validation failed)/i,
      validate: function (line) {
        return /(?:code signature invalid|invalid code signature|signature validation failed)/i.test(line) &&
          /\b(amfi|codesign|executable|process|bundle|application)\b/i.test(line);
      }
    },
    {
      id: "modified_executable",
      name: "Ejecutable posiblemente modificado",
      category: "Integridad de aplicaciones",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation:
        "Se encontró una referencia a un ejecutable sin firma válida. Es necesario identificar la aplicación y comprobar el origen del registro.",
      pattern:
        /\bunsigned executable\b/i,
      validate: function (line) {
        return /\bunsigned executable\b/i.test(line) &&
          /\b(path|process|bundle|application|amfi|executable)\b/i.test(line);
      }
    }
  ];

  // ======================================
  // UTILIDADES
  // ======================================

  function isTextFile(name) {
    const lower = String(name).toLowerCase();

    return TEXT_EXTENSIONS.some(function (ext) {
      return lower.endsWith(ext);
    }) ||
      lower.includes("log") ||
      lower.includes("panic") ||
      lower.includes("crash");
  }

  function cleanPath(path) {
    return String(path)
      .replace(/\\/g, "/")
      .replace(/\0/g, "")
      .slice(0, 500);
  }

  function cleanEvidence(line) {
    return String(line)
      .replace(/\0/g, "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 350);
  }

  // ======================================
  // ANALISIS CONTEXTUAL
  // ======================================

  function analyzeText(text, filePath) {
    const findings = [];
    const lines = String(text).split(/\r?\n/);

    for (const rule of RULES) {
      const evidence = [];
      const seen = new Set();

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (!rule.pattern.test(line)) {
          continue;
        }

        if (!rule.validate(line)) {
          continue;
        }

        const excerpt = cleanEvidence(line);

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

        const chunk = result.value;
        this.totalRead += chunk.byteLength;

        if (this.totalRead > this.maxBytes) {
          throw new Error(
            "El archivo descomprimido supera el límite de seguridad de 2 GB."
          );
        }

        this.chunks.push(chunk);
        this.available += chunk.byteLength;
      }
    }

    consume(length, destination, destinationOffset) {
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
            destinationOffset + written
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
      this.consume(length, output, 0);

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

        this.consume(amount, null, 0);
        remaining -= amount;
      }
    }

    async cancel() {
      try {
        await this.reader.cancel();
      } catch {
        // Flujo ya cerrado.
      }
    }
  }

  // ======================================
  // LECTURA DEL TAMAÑO TAR
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
      throw new Error(
        "El archivo TAR contiene un tamaño inválido."
      );
    }

    return value;
  }

  // ======================================
  // ANALIZAR TAR.GZ PROGRESIVAMENTE
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
          isTextFile(path) &&
          size <= MAX_FILE_SIZE;

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

          totalTextSize += data.byteLength;

          const text = new TextDecoder(
            "utf-8",
            { fatal: false }
          ).decode(data);

          inspected.push(cleanPath(path));

          findings.push(
            ...analyzeText(text, path)
          );

        } else {
          if (
            eligible &&
            (!withinTotalLimit || !withinFileLimit)
          ) {
            truncated = true;
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
        truncated
      };

    } finally {
      await source.cancel();
    }
  }

  // ======================================
  // ANALIZAR ZIP
  // ======================================

  async function analyzeZip(file) {
    if (!window.JSZip) {
      throw new Error(
        "Falta cargar la biblioteca JSZip."
      );
    }

    const archive = await window.JSZip.loadAsync(file);

    const findings = [];
    const inspected = [];

    let totalSize = 0;
    let truncated = false;
    let entries = 0;

    for (const [path, entry] of Object.entries(archive.files)) {
      entries++;

      if (entry.dir || !isTextFile(path)) {
        continue;
      }

      if (inspected.length >= MAX_INSPECTED_FILES) {
        truncated = true;
        break;
      }

      if (
        entry._data &&
        entry._data.uncompressedSize > MAX_FILE_SIZE
      ) {
        continue;
      }

      const text = await entry.async("string");
      const size = new Blob([text]).size;

      if (size > MAX_FILE_SIZE) {
        continue;
      }

      if (totalSize + size > MAX_TOTAL_TEXT_SIZE) {
        truncated = true;
        break;
      }

      totalSize += size;
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
      truncated
    };
  }

  // ======================================
  // DESCOMPRESION GZIP
  // ======================================

  async function analyzeGzip(file) {
    if (typeof DecompressionStream === "undefined") {
      throw new Error(
        "Este navegador no permite descomprimir GZIP. Actualiza Safari."
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
      throw new Error(
        "Formato no compatible con este motor."
      );
    }

    const categories = [
      ...new Set(
        result.findings.map(item => item.category)
      )
    ];

    const highCount = result.findings.filter(
      item => item.severity === "high"
    ).length;

    const mediumCount = result.findings.filter(
      item => item.severity === "medium"
    ).length;

    return {
      engine: "J-SCANNER IPHONE",
      version: "1.2",

      fileName: file.name,
      fileSize: file.size,

      scannedFiles: result.inspected.length,
      findings: result.findings,
      categories: categories,

      highRiskCount: highCount,
      mediumRiskCount: mediumCount,

      entriesProcessed: result.entries,
      truncated: result.truncated,

      status: result.findings.length
        ? "REVIEW_REQUIRED"
        : "NO_INDICATORS_FOUND",

      disclaimer:
        "J-Scanner encontró referencias técnicas que pueden requerir revisión. Los indicadores no demuestran por sí solos el uso de hacks ni modificaciones de Free Fire. Este análisis examina archivos de texto disponibles en el Sysdiagnose y no accede a los datos privados ni verifica directamente la integridad del juego. Puede haber falsos positivos y falsos negativos."
    };
  }

  // ======================================
  // EXPORTAR MOTOR
  // ======================================

  window.JScannerIPhone = {
    scan: scan,
    version: "1.2"
  };

})();
