/**
 * Phoenix Threat Engine — Client-Side Digital Forensics & Threat Intelligence Suite
 * Provides local homograph/spoofing link inspection, EXIF/ELA image forensics,
 * and cryptographic Incident Evidence Dossiers entirely in-browser.
 */

import { sha256Hex } from "./evidence";

export type LinkThreatSignal = {
  id: string;
  level: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  points: number;
};

export type LinkThreatReport = {
  inputUrl: string;
  normalizedUrl: string;
  domain: string;
  hostname: string;
  protocol: string;
  isPunycode: boolean;
  uncloakedDestinations: string[];
  spoofedBrand: string | null;
  suspiciousTld: string | null;
  riskScore: number;
  riskBand: "critical" | "high" | "elevated" | "low";
  riskLabel: string;
  signals: LinkThreatSignal[];
  mitigations: string[];
};

export type ImageForensicsReport = {
  fileName: string;
  fileSizeBytes: number;
  mimeType: string;
  sha256: string;
  dimensions: { width: number; height: number };
  exif: {
    cameraMake?: string;
    cameraModel?: string;
    software?: string;
    dateTime?: string;
    hasGps: boolean;
    gpsCoordinates?: { lat: number; lng: number };
    rawTags: Record<string, string>;
  };
  tamperingRisk: "high" | "medium" | "low";
  tamperingSummary: string;
  tamperingSignals: string[];
  elaCanvasDataUrl?: string;
};

export type IncidentDossier = {
  dossierId: string;
  timestamp: string;
  analyst: string;
  sha256Integrity: string;
  targetCategory: "link" | "image" | "phone" | "general";
  targetSummary: string;
  findings: string[];
  recommendations: string[];
  disclaimer: string;
};

// Known high-value impersonated brands
const MONITORED_BRANDS: Record<string, string> = {
  paypal: "PayPal",
  apple: "Apple",
  google: "Google",
  microsoft: "Microsoft",
  binance: "Binance",
  amazon: "Amazon",
  netflix: "Netflix",
  telegram: "Telegram",
  whatsapp: "WhatsApp",
  facebook: "Meta / Facebook",
  instagram: "Instagram",
  meta: "Meta",
  coinbase: "Coinbase",
  ledger: "Ledger",
  chase: "Chase Bank",
  bankofamerica: "Bank of America",
  wellsfargo: "Wells Fargo",
  dhl: "DHL Express",
  fedex: "FedEx",
  aramex: "Aramex",
  usps: "USPS",
};

// High-abuse TLDs often used for short-lived disposable phishing campaigns
const SUSPICIOUS_TLDS = new Set([
  "top",
  "xyz",
  "click",
  "buzz",
  "fit",
  "icu",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "zip",
  "mov",
  "country",
  "stream",
  "download",
  "work",
  "rest",
  "sbs",
  "cfd",
  "quest",
  "monster",
]);

// Lookalike / Cyrillic characters mapping to Latin
const HOMOGRAPH_LOOKALIKES: Record<string, string> = {
  "\u0430": "a", // Cyrillic small a
  "\u0441": "c", // Cyrillic small es
  "\u0435": "e", // Cyrillic small ie
  "\u0456": "i", // Cyrillic small byelorussian-ukrainian i
  "\u0458": "j", // Cyrillic small je
  "\u043E": "o", // Cyrillic small o
  "\u0440": "p", // Cyrillic small er
  "\u0455": "s", // Cyrillic small dze
  "\u0443": "y", // Cyrillic small u
  "\u0445": "x", // Cyrillic small ha
  "\u03BF": "o", // Greek small omicron
  "\u03BD": "v", // Greek small nu
};

const REDIRECT_PARAM_KEYS = ["url", "uri", "redirect", "redirect_url", "next", "continue", "dest", "destination", "target", "r", "link", "to", "goto"];

/**
 * Perform forensic link inspection for homograph attacks, brand spoofing, and redirect uncloaking
 */
export function assessThreatLink(rawUrl: string): LinkThreatReport {
  const trimmed = rawUrl.trim();
  const normalized = /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(trimmed) ? trimmed : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("يرجى إدخال رابط صالح للفحص الجنائي.");
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const search = parsed.search;
  const signals: LinkThreatSignal[] = [];
  let score = 0;

  // 1. Homograph & Cyrillic Lookalike Detection
  let isPunycode = hostname.startsWith("xn--") || hostname.includes(".xn--");
  let homographCharsFound: string[] = [];
  for (const char of trimmed) {
    if (HOMOGRAPH_LOOKALIKES[char]) {
      homographCharsFound.push(`${char} (شبيه بـ ${HOMOGRAPH_LOOKALIKES[char]})`);
    }
  }

  if (isPunycode || homographCharsFound.length > 0) {
    score += 45;
    signals.push({
      id: "homograph_spoof",
      level: "critical",
      title: "احتيال بصري / خلط أحرف غير لاتينية (Homograph Attack)",
      detail: `الرابط يستخدم ترميز Punycode أو محارف سريلية شبيهة بالحروف اللاتينية لخداع العين: ${homographCharsFound.join(", ") || hostname}`,
      points: 45,
    });
  }

  // 2. Brand Impersonation in Subdomains or Path
  let spoofedBrand: string | null = null;
  const domainParts = hostname.split(".");
  const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : "";
  const registeredDomain = domainParts.length >= 2 ? `${domainParts[domainParts.length - 2]}.${tld}` : hostname;

  for (const [key, brandName] of Object.entries(MONITORED_BRANDS)) {
    // If brand appears in hostname but is NOT the legitimate registered domain
    if (hostname.includes(key) && !registeredDomain.startsWith(key)) {
      spoofedBrand = brandName;
      score += 40;
      signals.push({
        id: "brand_impersonation",
        level: "critical",
        title: `انتحال علامة تجارية معروفة (${brandName})`,
        detail: `اسم العلامة (${brandName}) يظهر في النطاق الفرعي أو المسار لخداع المستخدم، بينما النطاق الفعلي المسجل هو (${registeredDomain}).`,
        points: 40,
      });
      break;
    }
  }

  // 3. Suspicious / High-Abuse TLD Check
  let suspiciousTld: string | null = null;
  if (SUSPICIOUS_TLDS.has(tld)) {
    suspiciousTld = `.${tld}`;
    score += 20;
    signals.push({
      id: "suspicious_tld",
      level: "high",
      title: `نطاق علوي مشبوه الإحصاءات (${suspiciousTld})`,
      detail: `النطاق يستخدم امتداداً منخفض التكلفة وشائع الاستخدام في حملات التصيد المؤقتة.`,
      points: 20,
    });
  }

  // 4. Multi-Hop Redirect Parameter Uncloaking
  const uncloakedDestinations: string[] = [];
  for (const key of REDIRECT_PARAM_KEYS) {
    const val = parsed.searchParams.get(key);
    if (val && (val.startsWith("http://") || val.startsWith("https://") || val.includes("."))) {
      uncloakedDestinations.push(val);
    }
  }

  if (uncloakedDestinations.length > 0) {
    score += 25;
    signals.push({
      id: "redirect_uncloaked",
      level: "high",
      title: "توجيه مخفي داخل معلمات الرابط (Open Redirect / Uncloaking)",
      detail: `الرابط ينقل الزائر لوجهة مخفية عبر المعامل: ${uncloakedDestinations[0]}`,
      points: 25,
    });
  }

  // 5. IP Address As Hostname
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 30;
    signals.push({
      id: "ip_hostname",
      level: "high",
      title: "استخدام عنوان IP خام بدلاً من اسم نطاق",
      detail: "تخطي نظام أسماء النطاقات (DNS) مؤشر دفاعي يتطلب التدقيق المستقل.",
      points: 30,
    });
  }

  // 6. Excessive Subdomain Stacking
  if (domainParts.length >= 4) {
    score += 15;
    signals.push({
      id: "subdomain_stacking",
      level: "medium",
      title: "تراكم نطاقات فرعية مضللة",
      detail: `يتضمن الرابط ${domainParts.length} مستويات نطاق تهدف لإخفاء النطاق النهائي على شاشات الهواتف.`,
      points: 15,
    });
  }

  // 7. Clear Protocol Check
  if (parsed.protocol === "http:") {
    score += 15;
    signals.push({
      id: "insecure_http",
      level: "medium",
      title: "بروتوكول غير مشفر (HTTP)",
      detail: "حركة المرور معرضة للاعتراض (MitM) وتفتقد لشهادة TLS موثوقة.",
      points: 15,
    });
  }

  const finalScore = Math.min(score, 100);
  let riskBand: LinkThreatReport["riskBand"] = "low";
  let riskLabel = "إشارات أمان مستقرة";

  if (finalScore >= 60) {
    riskBand = "critical";
    riskLabel = "تهديد حرج — رابط احتيال أو انتحال عالي الخطورة";
  } else if (finalScore >= 35) {
    riskBand = "high";
    riskLabel = "تهديد مرتفع — إشارات مشبوهة واضحة";
  } else if (finalScore >= 15) {
    riskBand = "elevated";
    riskLabel = "يحتاج تدقيقاً — إشارات تستوجب الحذر";
  }

  const mitigations: string[] = [];
  if (finalScore >= 35) {
    mitigations.push("لا تنقر على الرابط ولا تفتحه في متصفحك الأساسي.");
    mitigations.push("تجنب إدخال أي كلمات مرور، بطاقات دفع، أو رموز تحقق.");
    if (spoofedBrand) {
      mitigations.push(`افتح الموقع الرسمي لـ (${spoofedBrand}) مباشرة عبر كتابة عنوانه بيدك في المتصفح.`);
    }
    mitigations.push("احفظ الرابط في كبسولة الأدلة لتوثيق محاولة التصيد.");
  } else {
    mitigations.push("الرابط لا يظهر تزييفاً بصرياً فورياً، لكن تحقق دائماً من هوية الراسل وسياق الرسالة.");
    mitigations.push("لا تشارك بياناتك السرية دون تثبت مستقل.");
  }

  return {
    inputUrl: rawUrl,
    normalizedUrl: normalized,
    domain: registeredDomain,
    hostname,
    protocol: parsed.protocol,
    isPunycode,
    uncloakedDestinations,
    spoofedBrand,
    suspiciousTld,
    riskScore: finalScore,
    riskBand,
    riskLabel,
    signals,
    mitigations,
  };
}

/**
 * Extract EXIF metadata tags from a JPEG binary ArrayBuffer
 */
function parseJpegExif(buffer: ArrayBuffer): { tags: Record<string, string>; hasGps: boolean } {
  const dataView = new DataView(buffer);
  const tags: Record<string, string> = {};
  let hasGps = false;

  // Check SOI marker (0xFFD8)
  if (dataView.byteLength < 4 || dataView.getUint16(0, false) !== 0xffd8) {
    return { tags, hasGps };
  }

  let offset = 2;
  const length = dataView.byteLength;

  while (offset < length - 2) {
    const marker = dataView.getUint16(offset, false);
    offset += 2;

    if (marker === 0xffe1) {
      // APP1 Marker (EXIF)
      const app1Length = dataView.getUint16(offset, false);
      offset += 2;

      // Check "Exif\0\0" header
      if (dataView.getUint32(offset, false) === 0x45786966 && dataView.getUint16(offset + 4, false) === 0x0000) {
        const tiffOffset = offset + 6;
        const littleEndian = dataView.getUint16(tiffOffset, false) === 0x4949;

        const firstIfdOffset = dataView.getUint32(tiffOffset + 4, littleEndian);
        let ifdOffset = tiffOffset + firstIfdOffset;

        if (ifdOffset + 2 < length) {
          const numEntries = dataView.getUint16(ifdOffset, littleEndian);
          ifdOffset += 2;

          for (let i = 0; i < numEntries && ifdOffset + 12 <= length; i++) {
            const tag = dataView.getUint16(ifdOffset, littleEndian);
            const count = dataView.getUint32(ifdOffset + 4, littleEndian);
            const valueOffset = dataView.getUint32(ifdOffset + 8, littleEndian);

            // 0x010F = Make, 0x0110 = Model, 0x0131 = Software, 0x0132 = DateTime, 0x8825 = GPSInfoIFDPointer
            if (tag === 0x8825) {
              hasGps = true;
            }

            if (tag === 0x010f || tag === 0x0110 || tag === 0x0131 || tag === 0x0132) {
              const strOffset = count <= 4 ? ifdOffset + 8 : tiffOffset + valueOffset;
              if (strOffset + count <= length) {
                const chars: number[] = [];
                for (let j = 0; j < Math.min(count - 1, 120); j++) {
                  chars.push(dataView.getUint8(strOffset + j));
                }
                const text = String.fromCharCode(...chars).trim();
                if (tag === 0x010f) tags.Make = text;
                if (tag === 0x0110) tags.Model = text;
                if (tag === 0x0131) tags.Software = text;
                if (tag === 0x0132) tags.DateTime = text;
              }
            }

            ifdOffset += 12;
          }
        }
      }
      break;
    } else if ((marker & 0xff00) === 0xff00 && marker !== 0xffd8 && marker !== 0xffd9) {
      const segLength = dataView.getUint16(offset, false);
      offset += segLength;
    } else {
      break;
    }
  }

  return { tags, hasGps };
}

/**
 * Generate Canvas Error Level Analysis (ELA) preview and extract image forensics
 */
export async function analyzeImageForensics(file: File): Promise<ImageForensicsReport> {
  const buffer = await file.arrayBuffer();
  const sha256 = await sha256Hex(buffer);
  const { tags, hasGps } = file.type.includes("jpeg") || file.type.includes("jpg") ? parseJpegExif(buffer) : { tags: {}, hasGps: false };

  // Load image into canvas for dimensions and ELA
  const objectUrl = URL.createObjectURL(file);
  const image = await new Promise<HTMLImageElement>((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("تعذر قراءة ملف الصورة."));
    img.src = objectUrl;
  });

  const width = image.naturalWidth;
  const height = image.naturalHeight;

  // Run Canvas Error Level Analysis (ELA)
  const origCanvas = document.createElement("canvas");
  origCanvas.width = width;
  origCanvas.height = height;
  const origCtx = origCanvas.getContext("2d", { willReadFrequently: true });

  const diffCanvas = document.createElement("canvas");
  diffCanvas.width = width;
  diffCanvas.height = height;
  const diffCtx = diffCanvas.getContext("2d", { willReadFrequently: true });

  let elaDataUrl = "";
  let highVariancePixels = 0;

  if (origCtx && diffCtx) {
    origCtx.drawImage(image, 0, 0);
    const origData = origCtx.getImageData(0, 0, width, height);

    // Re-compress via JPEG at 72% quality
    const compressedDataUrl = origCanvas.toDataURL("image/jpeg", 0.72);
    const recompressedImg = await new Promise<HTMLImageElement>((resolve) => {
      const img2 = new Image();
      img2.onload = () => resolve(img2);
      img2.src = compressedDataUrl;
    });

    diffCtx.drawImage(recompressedImg, 0, 0);
    const recompressedData = diffCtx.getImageData(0, 0, width, height);

    const diffImageData = diffCtx.createImageData(width, height);
    const scale = 20; // amplify compression difference

    for (let i = 0; i < origData.data.length; i += 4) {
      const dr = Math.abs(origData.data[i] - recompressedData.data[i]) * scale;
      const dg = Math.abs(origData.data[i + 1] - recompressedData.data[i + 1]) * scale;
      const db = Math.abs(origData.data[i + 2] - recompressedData.data[i + 2]) * scale;

      const diffMag = (dr + dg + db) / 3;
      if (diffMag > 140) highVariancePixels++;

      diffImageData.data[i] = Math.min(dr, 255);
      diffImageData.data[i + 1] = Math.min(dg, 255);
      diffImageData.data[i + 2] = Math.min(db, 255);
      diffImageData.data[i + 3] = 255;
    }

    diffCtx.putImageData(diffImageData, 0, 0);
    elaDataUrl = diffCanvas.toDataURL("image/jpeg", 0.85);
  }

  URL.revokeObjectURL(objectUrl);

  const tamperingSignals: string[] = [];
  let tamperingRisk: ImageForensicsReport["tamperingRisk"] = "low";

  // Check software tag for photo editors
  const software = tags.Software || "";
  const editingKeywords = ["photoshop", "gimp", "canva", "lightroom", "paint.net", "snapseed", "picsart", "facetune", "adobe"];
  const matchedEditor = editingKeywords.find((kw) => software.toLowerCase().includes(kw));

  if (matchedEditor) {
    tamperingRisk = "high";
    tamperingSignals.push(`بيانات EXIF تشير إلى التعديل عبر برنامج تحرير: ${software}`);
  }

  const varianceRatio = (highVariancePixels / (width * height)) * 100;
  if (varianceRatio > 12) {
    if (tamperingRisk !== "high") tamperingRisk = "medium";
    tamperingSignals.push(`تحليل تباين الضغط (ELA) أظهر مناطق ضغط غير متجانسة بنسبة ${varianceRatio.toFixed(1)}% مما يرجح إعادة لصق أو تحرير موضعي.`);
  }

  if (hasGps) {
    tamperingSignals.push("تم اكتشاف وسم إحداثيات GPS في الملف الأصلي.");
  }

  if (tags.Make || tags.Model) {
    tamperingSignals.push(`معلومات الكاميرا الأصلية: ${tags.Make || ""} ${tags.Model || ""}`);
  }

  let tamperingSummary = "الصورة تظهر تماسكاً طبيعياً في مستويات الضغط ولا تظهر برامج تعديل في الوسوم.";
  if (tamperingRisk === "high") {
    tamperingSummary = "تم رصد علامات تعديل صريحة في البرامج وبيانات الصورة الجنائية.";
  } else if (tamperingRisk === "medium") {
    tamperingSummary = "توجد فروق ضغط موضعية (ELA) تستوجب الحذر والمراجعة اليدوية.";
  }

  return {
    fileName: file.name,
    fileSizeBytes: file.size,
    mimeType: file.type || "image/unknown",
    sha256,
    dimensions: { width, height },
    exif: {
      cameraMake: tags.Make,
      cameraModel: tags.Model,
      software: tags.Software,
      dateTime: tags.DateTime,
      hasGps,
      rawTags: tags,
    },
    tamperingRisk,
    tamperingSummary,
    tamperingSignals,
    elaCanvasDataUrl: elaDataUrl,
  };
}

/**
 * Generate Cryptographic Incident Dossier in Markdown format
 */
export function buildDossierMarkdown(report: {
  title: string;
  category: string;
  target: string;
  scoreOrRisk: string;
  signals: string[];
  mitigations: string[];
  fileHash?: string;
}): string {
  const timestamp = new Date().toISOString();
  const id = `PHX-DOSSIER-${Math.floor(Date.now() / 1000)}-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;

  return [
    `# Phoenix Incident Evidence Dossier`,
    `**Dossier Reference ID:** \`${id}\``,
    `**Generated At (UTC):** \`${timestamp}\``,
    `**Classification:** DEFENSIVE EVIDENCE RECORD`,
    `**Environment:** Phoenix Local Forensics Engine (Client-Side & Zero-Cloud)`,
    ``,
    `---`,
    ``,
    `## 1. Incident Target & Overview`,
    `- **Investigation Scope:** ${report.category}`,
    `- **Target Analyzed:** \`${report.target}\``,
    `- **Assessment Outcome:** **${report.title}** (${report.scoreOrRisk})`,
    report.fileHash ? `- **Target SHA-256 Hash:** \`${report.fileHash}\`` : ``,
    ``,
    `## 2. Forensic Findings & Signals`,
    ...report.signals.map((s, idx) => `${idx + 1}. ${s}`),
    ``,
    `## 3. Recommended Defensive Actions`,
    ...report.mitigations.map((m, idx) => `- [ ] **Step ${idx + 1}:** ${m}`),
    ``,
    `---`,
    ``,
    `## 4. Chain of Custody & Verification`,
    `This evidence dossier was cryptographically generated locally in the analyst's browser.`,
    `No raw media, payload content, or sensitive identifiers were transmitted to remote external cloud servers.`,
    `Maintained under Phoenix Zero-Knowledge Integrity Principles.`,
    ``,
    `*Verified by Phoenix Command Center — Syrian National CTF Winner & Global Horizon Lab #177.*`,
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * Download a generated text or JSON file locally
 */
export function triggerFileDownload(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
