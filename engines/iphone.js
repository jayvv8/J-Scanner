
/*
========================================
 J-SCANNER
 IPHONE DIAGNOSTIC ENGINE
 Version 1.1
 STREAMING TAR.GZ SCANNER
========================================
*/

(function () {
  "use strict";

  // ======================================
  // LÍMITES DE SEGURIDAD
  // ======================================

  const MAX_FILE_SIZE = 2 * 1024 * 1024;

  const MAX_TOTAL_TEXT_SIZE =
    80 * 1024 * 1024;

  const MAX_DECOMPRESSED_SIZE =
    2 * 1024 * 1024 * 1024;

  const MAX_ORIGINAL_SIZE =
    1024 * 1024 * 1024;

  const MAX_ENTRIES = 50000;

  const MAX_INSPECTED_FILES = 10000;

  // ======================================
  // INDICADORES
  // ======================================

  const INDICATORS = [
    {
      name: "Jailbreak",
      category: "Sistema",
      severity: "warning",
      patterns: [
        /\bjailbreak\b/gi,
        /\bcydia\b/gi,
        /\bsileo\b/gi,
        /\bzebra\b/gi
      ]
    },
    {
      name: "Framework de modificación",
      category: "Modificación",
      severity: "warning",
      patterns: [
        /\bsubstrate\b/gi,
        /\bsubstitute\b/gi,
        /\bellekit\b/gi,
        /\blibhooker\b/gi
      ]
    },
    {
      name: "Herramientas de instrumentación",
      category: "Inyección",
      severity: "warning",
      patterns: [
        /\bfrida\b/gi,
        /\bdylib\b/gi,
        /DYLD_INSERT_LIBRARIES/gi,
        /\binjection\b/gi
      ]
    },
    {
      name: "Modificaciones de aplicaciones",
      category: "Aplicaciones",
      severity: "info",
      patterns: [
        /\bmodified application\b/gi,
        /\bunsigned executable\b/gi,
        /\bcode signature invalid\b/gi
      ]
    }
  ];

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
  // UTILIDADES
  // ======================================

  function isTextFile(name) {
    const lower = name.toLowerCase();

    return (
      TEXT_EXTENSIONS.some(ext =>
        lower.endsWith(ext)
      ) ||
      lower.includes("log") ||
      lower.includes("panic") ||
      lower.includes("crash")
    );
  }

  function cleanPath(path) {
    return String(path)
      .replace(/\\/g, "/")
      .slice(0, 300);
  }

  function analyzeText(text, filePath) {
    const findings = [];

    for (const indicator of INDICATORS) {
      let matches = 0;

      for (const pattern of indicator.patterns) {
        pattern.lastIndex = 0;

        const found = text.match(pattern);

        if (found) {
          matches += found.length;
        }
      }

      if (matches > 0) {
        findings.push({
          name: indicator.name,
          category: indicator.category,
          severity: indicator.severity,
          file: cleanPath(filePath),
          occurrences: matches,
          confidence:
            "Baja: requiere verificación manual"
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
      while (
        this.available < minimum &&
        !this.done
      ) {
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

        if (
          this.firstOffset >= chunk.byteLength
        ) {
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
        // El flujo puede estar cerrado.
      }
    }
  }

  // ======================================
  // LECTURA DE TAMAÑO TAR
  // ======================================

  function parseTarSize(bytes) {
    // Formato base-256 de TAR

    if (bytes[0] & 0x80) {
      let value = 0;

      for (let i = 0; i < bytes.length; i++) {
        const byte =
          i === 0
            ? bytes[i] & 0x7f
            : bytes[i];

        value = value * 256 + byte;

        if (!Number.isSafeInteger(value)) {
          throw new Error(
            "Tamaño TAR no compatible."
          );
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

    if (
      !Number.isSafeInteger(value) ||
      value < 0
    ) {
      throw new Error(
        "El archivo TAR contiene un tamaño inválido."
      );
    }

    return value;
  }

  // ======================================
  // ANALIZAR TAR PROGRESIVAMENTE
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
          type === "\0" ||
          type === "0";

        const padding =
          (512 - (size % 512)) % 512;

        const canInspect =
          regularFile &&
          isTextFile(path) &&
          size <= MAX_FILE_SIZE &&
          totalTextSize + size <=
            MAX_TOTAL_TEXT_SIZE &&
          inspected.length <
            MAX_INSPECTED_FILES;

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
          await source.skip(size);
        }

        if (padding > 0) {
          await source.skip(padding);
        }

        if (
          inspected.length >= MAX_INSPECTED_FILES
        ) {
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

    const archive =
      await window.JSZip.loadAsync(file);

    const findings = [];
    const inspected = [];

    let totalSize = 0;

    for (const [path, entry] of
      Object.entries(archive.files)) {

      if (entry.dir || !isTextFile(path)) {
        continue;
      }

      if (
        inspected.length >= MAX_INSPECTED_FILES
      ) {
        break;
      }

      if (
        entry._data &&
        entry._data.uncompressedSize >
          MAX_FILE_SIZE
      ) {
        continue;
      }

      const text = await entry.async("string");

      const size = new Blob([text]).size;

      if (size > MAX_FILE_SIZE) {
        continue;
      }

      totalSize += size;

      if (totalSize > MAX_TOTAL_TEXT_SIZE) {
        break;
      }

      inspected.push(path);

      findings.push(
        ...analyzeText(text, path)
      );
    }

    return {
      inspected,
      findings,
      totalSize,
      entries: inspected.length,
      truncated: false
    };
  }

  // ======================================
  // DESCOMPRESIÓN GZIP EN FLUJO
  // ======================================

  async function analyzeGzip(file) {
    if (
      typeof DecompressionStream === "undefined"
    ) {
      throw new Error(
        "Este navegador no permite descomprimir GZIP. Actualiza Safari o utiliza otro navegador compatible."
      );
    }

    const stream = file.stream().pipeThrough(
      new DecompressionStream("gzip")
    );

    return await analyzeTarStream(stream);
  }

  // ======================================
  // FUNCIÓN PRINCIPAL
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
        result.findings.map(
          item => item.category
        )
      )
    ];

    return {
      engine: "J-SCANNER IPHONE",
      version: "1.1",

      fileName: file.name,
      fileSize: file.size,

      scannedFiles: result.inspected.length,
      findings: result.findings,
      categories,

      entriesProcessed: result.entries,
      truncated: result.truncated,

      status: result.findings.length
        ? "REVIEW_REQUIRED"
        : "NO_INDICATORS_FOUND",

      disclaimer:
        "La ausencia de indicadores no demuestra que el dispositivo esté libre de hacks. Las coincidencias son indicios y requieren verificación manual. El análisis puede no incluir todos los archivos del diagnóstico."
    };
  }

  // ======================================
  // EXPORTAR MOTOR
  // ======================================

  window.JScannerIPhone = {
    scan,
    version: "1.1"
  };

})();
