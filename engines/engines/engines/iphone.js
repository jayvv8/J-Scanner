
/*
========================================
 J-SCANNER
 IPHONE DIAGNOSTIC ENGINE
 Version 1.0
========================================
*/

(function () {
  "use strict";

  const MAX_FILE_SIZE = 2 * 1024 * 1024;
  const MAX_TOTAL_SIZE = 80 * 1024 * 1024;

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

  function isTextFile(name) {
    const lower = name.toLowerCase();

    return (
      TEXT_EXTENSIONS.some(ext => lower.endsWith(ext)) ||
      lower.includes("log") ||
      lower.includes("panic") ||
      lower.includes("crash")
    );
  }

  function cleanPath(path) {
    return String(path).replace(/\\/g, "/").slice(0, 300);
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
          confidence: "Baja: requiere verificación manual"
        });
      }
    }

    return findings;
  }

  async function readTextFile(file) {
    if (file.size > MAX_FILE_SIZE) {
      return null;
    }

    try {
      return await file.async("string");
    } catch {
      return null;
    }
  }

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

    for (const [path, entry] of Object.entries(archive.files)) {
      if (entry.dir || !isTextFile(path)) {
        continue;
      }

      if (inspected.length >= 5000) {
        break;
      }

      if (entry._data && entry._data.uncompressedSize > MAX_FILE_SIZE) {
        continue;
      }

      const text = await readTextFile(entry);

      if (text === null) {
        continue;
      }

      totalSize += new Blob([text]).size;

      if (totalSize > MAX_TOTAL_SIZE) {
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
      totalSize
    };
  }

  function parseTar(buffer) {
    const bytes = new Uint8Array(buffer);
    const files = [];

    let offset = 0;

    while (offset + 512 <= bytes.length) {
      const header = bytes.subarray(offset, offset + 512);

      if (header.every(byte => byte === 0)) {
        break;
      }

      const name = new TextDecoder().decode(
        header.subarray(0, 100)
      ).replace(/\0.*$/, "");

      const sizeText = new TextDecoder().decode(
        header.subarray(124, 136)
      ).replace(/\0.*$/, "").trim();

      const size = parseInt(sizeText || "0", 8);

      if (!Number.isFinite(size) || size < 0) {
        break;
      }

      const dataStart = offset + 512;
      const dataEnd = dataStart + size;

      if (dataEnd > bytes.length) {
        break;
      }

      if (name && size <= MAX_FILE_SIZE) {
        files.push({
          name,
          data: bytes.subarray(dataStart, dataEnd)
        });
      }

      offset = dataStart + Math.ceil(size / 512) * 512;

      if (files.length >= 5000) {
        break;
      }
    }

    return files;
  }

  async function decompressGzip(file) {
    if (typeof DecompressionStream === "undefined") {
      throw new Error(
        "Este navegador no permite descomprimir GZIP."
      );
    }

    const stream = file.stream().pipeThrough(
      new DecompressionStream("gzip")
    );

    return await new Response(stream).arrayBuffer();
  }

  function analyzeTar(buffer) {
    const files = parseTar(buffer);

    const findings = [];
    const inspected = [];

    let totalSize = 0;

    for (const item of files) {
      if (!isTextFile(item.name)) {
        continue;
      }

      totalSize += item.data.byteLength;

      if (totalSize > MAX_TOTAL_SIZE) {
        break;
      }

      const text = new TextDecoder(
        "utf-8",
        { fatal: false }
      ).decode(item.data);

      inspected.push(item.name);

      findings.push(
        ...analyzeText(text, item.name)
      );
    }

    return {
      inspected,
      findings,
      totalSize
    };
  }

  async function scan(file) {
    if (!(file instanceof File)) {
      throw new Error("Archivo inválido.");
    }

    if (file.size > 1024 * 1024 * 1024) {
      throw new Error(
        "El archivo supera el límite de 1 GB."
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
      const buffer = await decompressGzip(file);

      if (buffer.byteLength > MAX_TOTAL_SIZE * 4) {
        throw new Error(
          "El archivo descomprimido supera el límite de seguridad."
        );
      }

      result = analyzeTar(buffer);

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

    return {
      engine: "J-SCANNER IPHONE",
      version: "1.0",
      fileName: file.name,
      fileSize: file.size,
      scannedFiles: result.inspected.length,
      findings: result.findings,
      categories,
      status: result.findings.length
        ? "REVIEW_REQUIRED"
        : "NO_INDICATORS_FOUND",
      disclaimer:
        "La ausencia de indicadores no demuestra que el dispositivo esté libre de hacks. Las coincidencias requieren verificación manual."
    };
  }

  window.JScannerIPhone = {
    scan,
    version: "1.0"
  };

})();
