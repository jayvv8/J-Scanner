
/*
========================================
 J-SCANNER
 IPHONE DIAGNOSTIC ENGINE
 VERSION 1.4
 FREE FIRE INDICATOR DETECTION
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
    ".txt", ".log", ".plist", ".json", ".xml",
    ".ips", ".crash", ".panic", ".csv"
  ];

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

    // INSTALADORES IPA

    {
      id: "esign_reference",
      name: "Referencia a ESign",
      category: "Instaladores IPA",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a ESign. Puede corresponder a una aplicación instalada, un registro histórico o una mención. No confirma su uso.",
      validate: line => /\besign\b/i.test(line)
    },

    {
      id: "gbox_reference",
      name: "Referencia a GBox",
      category: "Instaladores IPA",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a GBox. Debe verificarse el contexto y la aplicación relacionada.",
      validate: line => /\bgbox\b/i.test(line)
    },

    {
      id: "ksign_reference",
      name: "Referencia a KSign",
      category: "Instaladores IPA",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a KSign. No demuestra por sí sola que se haya instalado o utilizado.",
      validate: line => /\bksign\b/i.test(line)
    },

    {
      id: "trollstore_reference",
      name: "Referencia a TrollStore",
      category: "Instaladores IPA",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a TrollStore. Se necesita confirmar su origen y contexto.",
      validate: line => /\btroll\s*store\b/i.test(line)
    },

    {
      id: "trollfools_reference",
      name: "Referencia a TrollFools",
      category: "Instaladores IPA",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a TrollFools. No confirma que la herramienta esté activa.",
      validate: line => /\btroll\s*fools\b/i.test(line)
    },

    {
      id: "fluckstore_reference",
      name: "Referencia a FlucksStore",
      category: "Instaladores IPA",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a FlucksStore. Debe revisarse el registro original.",
      validate: line => /\bflucks?\s*store\b/i.test(line)
    },

    // HERRAMIENTAS EXTERNAS

    {
      id: "filza_reference",
      name: "Referencia a Filza",
      category: "Herramientas externas",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a Filza. Puede tratarse de una aplicación, una ruta o una mención histórica.",
      validate: line => /\bfilza(?:escaped)?\b/i.test(line)
    },

    {
      id: "flourite_reference",
      name: "Referencia a Flourite",
      category: "Herramientas externas",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a Flourite. Es necesario verificar el contexto para determinar su relación con el dispositivo.",
      validate: line => /\bflourite\b/i.test(line)
    },

    {
      id: "freefire_panel",
      name: "Referencia a panel de Free Fire",
      category: "Modificaciones de juego",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia que combina Free Fire con términos relacionados con paneles o modificaciones. No confirma que el panel haya sido ejecutado.",
      validate: line => /\b(?:free\s*fire|freefire|ff)\b/i.test(line) &&
        /\b(?:panel|mod menu|modmenu|hack|cheat)\b/i.test(line)
    },

    // JAILBREAK

    {
      id: "jailbreak_paths",
      name: "Ruta asociada a jailbreak",
      category: "Jailbreak",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una ruta asociada a herramientas de modificación de iOS. Debe verificarse su existencia y actividad.",
      validate: line => /\/(?:Applications\/(?:Cydia|Sileo|Zebra)\.app|Library\/MobileSubstrate(?:\/|$)|Library\/TweakInject(?:\/|$)|usr\/lib\/TweakInject(?:\/|$)|var\/jb(?:\/|$)|var\/containers\/Bundle\/tweaksupport(?:\/|$))/i.test(line)
    },

    {
      id: "jailbreak_tool",
      name: "Referencia a herramienta de jailbreak",
      category: "Jailbreak",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a una herramienta o componente relacionado con jailbreak. Una mención no demuestra que el dispositivo esté modificado.",
      validate: line => /\b(?:Cydia|Sileo|Zebra|Substrate|Substitute|ElleKit|libhooker|Dopamine|Palera1n|Checkra1n)\b/i.test(line)
    },

    // PROXY

    {
      id: "proxy_configuration",
      name: "Referencia a configuración Proxy",
      category: "Red",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a una configuración Proxy o a un servidor intermediario. Los proxies también pueden utilizarse legítimamente.",
      validate: line => /\b(?:HTTPEnable|HTTPProxy|HTTPPort|HTTPSProxy|HTTPSPort|ProxyServer|ProxyPort|ProxyAutoConfigURL|ProxyPACURL|proxy server|proxy configuration)\b/i.test(line)
    },

    {
      id: "proxy_address",
      name: "Referencia a dirección de Proxy",
      category: "Red",
      severity: "low",
      confidence: "Indicador contextual",
      explanation: "Se encontró una dirección o configuración que podría estar relacionada con un Proxy. Debe comprobarse su función.",
      validate: line => /\b(?:proxy|pac)\b/i.test(line) &&
        /(?:https?:\/\/|(?:\d{1,3}\.){3}\d{1,3}|localhost|127\.0\.0\.1)/i.test(line)
    },

    // DNS

    {
      id: "dns_configuration",
      name: "Referencia a configuración DNS",
      category: "Red",
      severity: "low",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a configuración DNS. El uso de DNS personalizado no demuestra manipulación ni uso de hacks.",
      validate: line => /\b(?:DNSConfiguration|DNSSettings|DNSServer|DNSResolver|nameserver|dns server|resolver address|PrivateDNS)\b/i.test(line)
    },

    {
      id: "custom_dns_address",
      name: "Posible dirección DNS personalizada",
      category: "Red",
      severity: "low",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a una dirección DNS. Se necesita determinar si es una configuración activa o una referencia histórica.",
      validate: line => /\bDNS\b/i.test(line) &&
        /(?:\d{1,3}\.){3}\d{1,3}/i.test(line)
    },

    // INSTRUMENTACION

    {
      id: "frida_artifact",
      name: "Artefacto específico de Frida",
      category: "Instrumentación",
      severity: "high",
      confidence: "Indicador fuerte",
      explanation: "Se encontró una referencia específica a un componente de Frida. Debe verificarse si corresponde a una herramienta activa o a un registro histórico.",
      validate: line => /\bfrida-(?:server|gadget|agent)\b/i.test(line) ||
        (
          /\bfrida\b/i.test(line) &&
          /\b(?:27042|27043|gadget|server|agent|attach|spawn)\b/i.test(line)
        )
    },

    {
      id: "dyld_injection",
      name: "Variable de carga dinámica",
      category: "Carga de bibliotecas",
      severity: "high",
      confidence: "Indicador fuerte",
      explanation: "Se encontró una asignación de DYLD_INSERT_LIBRARIES con una ruta. No demuestra por sí sola que una biblioteca haya sido cargada.",
      validate: line => /DYLD_INSERT_LIBRARIES\s*=\s*["']?\/[^;\s"']+/i.test(line)
    },

    {
      id: "injection_framework",
      name: "Framework de modificación",
      category: "Bibliotecas",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró una referencia a un framework relacionado con instrumentación o modificación de procesos.",
      validate: line => /\b(?:MobileSubstrate|Substitute|ElleKit|libhooker)\b/i.test(line) &&
        /\b(?:loaded|loading|injected|injection|dylib|mapped|process)\b/i.test(line)
    },

    {
      id: "signature_failure",
      name: "Error de validación de firma",
      category: "Integridad",
      severity: "medium",
      confidence: "Indicador contextual",
      explanation: "Se encontró un error relacionado con la validación de una firma de código. También puede deberse a errores legítimos.",
      validate: line => /(?:code signature invalid|invalid code signature|signature validation failed)/i.test(line) &&
        /\b(?:amfi|codesign|executable|process|bundle|application)\b/i.test(line)
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

    return SAFE_PATHS.some(safePath =>
      normalized.startsWith(safePath)
    );
  }

  function hasTextExtension(path) {
    const name = cleanPath(path).toLowerCase();
    const basename = name.split("/").pop();

    return TEXT_EXTENSIONS.some(extension =>
      basename.endsWith(extension)
    );
  }

  // ======================================
  // FILTRO BINARIO
  // ======================================

  function isProbablyText(bytes) {
    if (!bytes || bytes.length === 0) return false;

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
    const inspected = Math.min(bytes.length, 8192);

    for (let i = 0; i < inspected; i++) {
      const value = bytes[i];

      if (value === 0) return false;

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

    if (isSafePath(filePath)) return findings;

    for (const rule of RULES) {
      const evidence = [];
      const seen = new Set();

      for (let i = 0; i < lines.length; i++) {
        const originalLine = lines[i];

        if (!rule.validate(originalLine)) continue;

        const excerpt = cleanEvidence(originalLine);

        if (!excerpt || seen.has(excerpt)) continue;

        seen.add(excerpt);

        evidence.push({
          line: i + 1,
          text: excerpt
        });

        if (evidence.length >= MAX_EVIDENCE_PER_RULE) break;
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
      if (length === 0) return new Uint8Array(0);

      await this.fill(length);

      if (this.available < length) {
        if (this.available === 0) return null;

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
  // LECTOR TAR
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

        if (header.every(byte => byte === 0)) break;

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

          if (!eligible) skippedUnsupported++;

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

    const lowCount = result.findings.filter(
      item => item.severity === "low"
    ).length;

    const categories = [
      ...new Set(
        result.findings.map(item => item.category)
      )
    ];

    return {
      engine: "J-SCANNER IPHONE",
      version: "1.4",

      fileName: file.name,
      fileSize: file.size,

      scannedFiles: result.inspected.length,
      findings: result.findings,
      categories: categories,

      highRiskCount: highCount,
      mediumRiskCount: mediumCount,
      lowRiskCount: lowCount,

      entriesProcessed: result.entries,
      skippedBinary: result.skippedBinary,
      skippedUnsupported: result.skippedUnsupported,

      truncated: result.truncated,

      status: result.findings.length
        ? "REVIEW_REQUIRED"
        : "NO_INDICATORS_FOUND",

      disclaimer:
        "J-Scanner 1.4 busca referencias textuales relacionadas con instaladores IPA, herramientas externas, jailbreak, modificaciones de Free Fire, Proxy y DNS. Los indicadores requieren revisión manual y no demuestran por sí solos que una aplicación esté instalada o que se haya utilizado un hack. Los archivos binarios no se interpretan en esta versión. El análisis no accede a los datos privados de Free Fire ni verifica directamente su integridad. Puede haber falsos positivos y falsos negativos."
    };
  }

  // ======================================
  // EXPORTAR MOTOR
  // ======================================

  window.JScannerIPhone = {
    scan: scan,
    version: "1.4"
  };

})();
