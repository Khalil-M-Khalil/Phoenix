/**
 * Phoenix Threat & Forensics Station — Advanced Deep Link Spoofing & Image Forensics Workspace.
 */
import { useState, type ChangeEvent } from "react";
import {
  assessThreatLink,
  analyzeImageForensics,
  buildDossierMarkdown,
  triggerFileDownload,
  type LinkThreatReport,
  type ImageForensicsReport,
} from "@/lib/threat-engine";
import {
  ShieldAlert,
  Link2,
  Image as ImageIcon,
  FileCheck2,
  Download,
  Copy,
  Check,
  CircleAlert,
  AlertTriangle,
  Fingerprint,
  Camera,
  Cpu,
  Layers,
  Sparkles,
  ExternalLink,
} from "lucide-react";
import "@/evidence-capsule.css";

export function ThreatForensicsStation({ onActivity }: { onActivity: (msg: string) => void }) {
  const [activeTab, setActiveTab] = useState<"link" | "image" | "dossier">("link");

  // Link Threat State
  const [urlInput, setUrlInput] = useState("");
  const [linkReport, setLinkReport] = useState<LinkThreatReport | null>(null);
  const [linkError, setLinkError] = useState("");

  // Image Forensics State
  const [imageReport, setImageReport] = useState<ImageForensicsReport | null>(null);
  const [imageLoading, setImageLoading] = useState(false);
  const [imageError, setImageError] = useState("");
  const [showEla, setShowEla] = useState(true);

  // Copy State
  const [copied, setCopied] = useState(false);

  // Analyze Link
  function handleAnalyzeLink(targetUrl?: string) {
    const input = targetUrl || urlInput;
    setLinkError("");
    try {
      const report = assessThreatLink(input);
      setLinkReport(report);
      onActivity(`فُحص الرابط جنائياً: كُشفت ${report.signals.length} إشارات أمنية.`);
    } catch (err) {
      setLinkReport(null);
      setLinkError(err instanceof Error ? err.message : "تعذر فحص الرابط.");
    }
  }

  // Handle Image Upload
  async function handleImageUpload(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    setImageLoading(true);
    setImageError("");
    try {
      const report = await analyzeImageForensics(file);
      setImageReport(report);
      onActivity(`أُجري فحص ELA واستخراج بيانات EXIF للصورة: ${file.name}.`);
    } catch (err) {
      setImageReport(null);
      setImageError(err instanceof Error ? err.message : "تعذر تحليل الصورة.");
    } finally {
      setImageLoading(false);
    }
  }

  // Export Dossier
  function exportDossier(format: "md" | "json") {
    let title = "Phoenix Threat Dossier";
    let category = "General Threat Investigation";
    let target = urlInput || imageReport?.fileName || "Phoenix Target";
    let scoreOrRisk = "Review Required";
    let signals: string[] = [];
    let mitigations: string[] = [];
    let fileHash: string | undefined = undefined;

    if (activeTab === "link" && linkReport) {
      title = linkReport.riskLabel;
      category = "Deep Link & Brand Impersonation Forensic Analysis";
      target = linkReport.normalizedUrl;
      scoreOrRisk = `Risk Score: ${linkReport.riskScore}/100 [${linkReport.riskBand.toUpperCase()}]`;
      signals = linkReport.signals.map((s) => `${s.title}: ${s.detail}`);
      mitigations = linkReport.mitigations;
    } else if (activeTab === "image" && imageReport) {
      title = imageReport.tamperingSummary;
      category = "Digital Image Forgery & Error Level Analysis (ELA)";
      target = imageReport.fileName;
      fileHash = imageReport.sha256;
      scoreOrRisk = `Tampering Risk: ${imageReport.tamperingRisk.toUpperCase()}`;
      signals = imageReport.tamperingSignals;
      mitigations = [
        "قارن بصمة SHA-256 مع النسخ الأصلية المعتمدة.",
        "تأكد من مصدر ملف الصورة قبل اعتماده في أي إجراء قانوني أو تقني.",
        "راجع مناطق تباين ELA للتحقق من أي نصوص أو أشكال مدمجة لاحقاً.",
      ];
    } else {
      signals = ["تم فتح جلسة تحقيق جنائي بدون بيانات محددة."];
      mitigations = ["أدخل رابطاً أو ارفع صورة لإكمال ملف القضية."];
    }

    if (format === "md") {
      const mdContent = buildDossierMarkdown({ title, category, target, scoreOrRisk, signals, mitigations, fileHash });
      triggerFileDownload(`PHX-DOSSIER-${Date.now()}.md`, mdContent, "text/markdown");
      onActivity("تم تحميل ملف الأدلة بصيغة Markdown بنجاح.");
    } else {
      const jsonPayload = {
        dossierId: `PHX-${Date.now()}`,
        generatedAt: new Date().toISOString(),
        category,
        target,
        fileHash,
        scoreOrRisk,
        signals,
        mitigations,
        rawReport: activeTab === "link" ? linkReport : imageReport,
      };
      triggerFileDownload(`PHX-DOSSIER-${Date.now()}.json`, JSON.stringify(jsonPayload, null, 2), "application/json");
      onActivity("تم تحميل ملف الأدلة المشفر بصيغة JSON بنجاح.");
    }
  }

  // Copy Dossier
  async function copyDossierText() {
    let text = "";
    if (linkReport) {
      text = buildDossierMarkdown({
        title: linkReport.riskLabel,
        category: "Deep Link Analysis",
        target: linkReport.normalizedUrl,
        scoreOrRisk: `${linkReport.riskScore}/100`,
        signals: linkReport.signals.map((s) => `${s.title}: ${s.detail}`),
        mitigations: linkReport.mitigations,
      });
    } else if (imageReport) {
      text = buildDossierMarkdown({
        title: imageReport.tamperingSummary,
        category: "Image Forensics (EXIF / ELA)",
        target: imageReport.fileName,
        fileHash: imageReport.sha256,
        scoreOrRisk: imageReport.tamperingRisk,
        signals: imageReport.tamperingSignals,
        mitigations: ["راجع بصمة التجزئة وبيانات المصدر."],
      });
    }
    if (text) {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      onActivity("نُسخ ملف القضية إلى الحافظة.");
    }
  }

  return (
    <div className="evidence-capsule" style={{ width: "100%", margin: "0 auto" }}>
      {/* Station Header */}
      <div className="capsule-hero">
        <div className="capsule-mark">
          <ShieldAlert size={24} />
        </div>
        <div>
          <p>FORENSICS &amp; THREAT INTELLIGENCE STATION</p>
          <h3>محطة التهديدات المتقدمة والتحقيق الجنائي</h3>
          <span>فحص احتيال الروابط العميقة، كشف تزييف الهوية، وتحليل تلاعب الصور (EXIF / ELA) محلياً بدون خوادم خارجية.</span>
        </div>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          <button className="capsule-export" onClick={() => exportDossier("md")}>
            <Download size={14} /> ملف Markdown
          </button>
          <button className="capsule-export" onClick={() => exportDossier("json")}>
            <FileCheck2 size={14} /> ملف JSON
          </button>
        </div>
      </div>

      {/* Tabs Switcher */}
      <div style={{ display: "flex", gap: "4px", padding: "12px 20px", background: "rgba(5,12,13,0.5)", borderBottom: "1px solid rgba(210,225,219,0.12)" }}>
        <button
          onClick={() => setActiveTab("link")}
          style={{
            padding: "8px 16px",
            fontSize: "12px",
            fontWeight: "600",
            background: activeTab === "link" ? "#d5b76e" : "rgba(255,255,255,0.05)",
            color: activeTab === "link" ? "#071011" : "#cfded9",
            border: "1px solid rgba(210,225,219,0.2)",
            borderRadius: "6px",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "6px",
          }}
        >
          <Link2 size={15} /> فحص الروابط وانتحال العلامات
        </button>
        <button
          onClick={() => setActiveTab("image")}
          style={{
            padding: "8px 16px",
            fontSize: "12px",
            fontWeight: "600",
            background: activeTab === "image" ? "#d5b76e" : "rgba(255,255,255,0.05)",
            color: activeTab === "image" ? "#071011" : "#cfded9",
            border: "1px solid rgba(210,225,219,0.2)",
            borderRadius: "6px",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "6px",
          }}
        >
          <ImageIcon size={15} /> التحقيق الجنائي للصور (EXIF / ELA)
        </button>
      </div>

      {/* Content Body */}
      <div style={{ padding: "24px" }}>
        {/* ================= LINK FORENSICS TAB ================= */}
        {activeTab === "link" && (
          <div style={{ display: "grid", gap: "20px" }}>
            <div style={{ background: "rgba(10,18,19,0.9)", padding: "18px", borderRadius: "8px", border: "1px solid rgba(210,225,219,0.14)" }}>
              <label style={{ display: "block", color: "#d7ba71", fontSize: "11px", fontWeight: "700", marginBottom: "8px" }}>
                رابط للفحص الجنائي العميق (Deep Uncloaking &amp; Homograph Attack)
              </label>
              <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                <input
                  type="text"
                  dir="ltr"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="https://paypal.com-verify.account-security.xyz/login?dest=https://evil.com"
                  style={{
                    flex: "1",
                    minWidth: "260px",
                    padding: "12px 14px",
                    background: "#050b0c",
                    border: "1px solid rgba(210,225,219,0.22)",
                    borderRadius: "6px",
                    color: "#fff",
                    fontSize: "13px",
                    outline: "none",
                  }}
                />
                <button
                  onClick={() => handleAnalyzeLink()}
                  style={{
                    padding: "12px 20px",
                    background: "#d5b76e",
                    color: "#0a1112",
                    fontWeight: "700",
                    border: "none",
                    borderRadius: "6px",
                    cursor: "pointer",
                  }}
                >
                  فحص التهديدات
                </button>
              </div>

              {/* Sample Shortcuts */}
              <div style={{ display: "flex", gap: "8px", marginTop: "12px", alignItems: "center", flexWrap: "wrap" }}>
                <span style={{ color: "#7e9791", fontSize: "10px" }}>أمثلة هجمات حقيقية:</span>
                <button
                  onClick={() => {
                    const sample = "https://\u0440\u0430\u0443\u0440\u0430l.com/signin";
                    setUrlInput(sample);
                    handleAnalyzeLink(sample);
                  }}
                  style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(210,225,219,0.18)", color: "#b8c7c3", padding: "4px 8px", fontSize: "10px", borderRadius: "4px", cursor: "pointer" }}
                >
                  احتيال بصري Homograph (раypal.com)
                </button>
                <button
                  onClick={() => {
                    const sample = "https://apple.id-verify.security-notice.top/login?redirect=https://real-site.com";
                    setUrlInput(sample);
                    handleAnalyzeLink(sample);
                  }}
                  style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(210,225,219,0.18)", color: "#b8c7c3", padding: "4px 8px", fontSize: "10px", borderRadius: "4px", cursor: "pointer" }}
                >
                  انتحال Apple + تحويل مفتوح
                </button>
                <button
                  onClick={() => {
                    const sample = "http://185.193.65.12/update.exe";
                    setUrlInput(sample);
                    handleAnalyzeLink(sample);
                  }}
                  style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(210,225,219,0.18)", color: "#b8c7c3", padding: "4px 8px", fontSize: "10px", borderRadius: "4px", cursor: "pointer" }}
                >
                  عنوان IP خام بدون SSL
                </button>
              </div>
            </div>

            {linkError && (
              <div style={{ padding: "12px", background: "rgba(239,68,68,0.15)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: "6px", color: "#fca5a5", fontSize: "12px", display: "flex", gap: "8px", alignItems: "center" }}>
                <CircleAlert size={16} /> {linkError}
              </div>
            )}

            {/* Link Report Card */}
            {linkReport && (
              <div style={{ background: "linear-gradient(160deg, #122021, #0a1213)", padding: "20px", borderRadius: "8px", border: "1px solid rgba(210,225,219,0.18)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "10px" }}>
                  <div>
                    <span style={{ fontSize: "10px", letterSpacing: "0.1em", color: "#d5b76e", fontWeight: "700" }}>PHOENIX THREAT INTELLIGENCE VERDICT</span>
                    <h4 style={{ margin: "4px 0 0", color: linkReport.riskBand === "critical" ? "#ef4444" : linkReport.riskBand === "high" ? "#f97316" : "#e5ddc1", fontSize: "17px" }}>
                      {linkReport.riskLabel}
                    </h4>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <div style={{ textAlign: "right" }}>
                      <span style={{ fontSize: "10px", color: "#8aa29c", display: "block" }}>مستوى الخطورة</span>
                      <strong style={{ fontSize: "20px", color: linkReport.riskScore >= 60 ? "#ef4444" : "#e5ddc1" }}>{linkReport.riskScore} / 100</strong>
                    </div>
                    <button
                      onClick={copyDossierText}
                      style={{ padding: "8px 12px", background: "rgba(255,255,255,0.08)", border: "1px solid rgba(210,225,219,0.2)", borderRadius: "6px", color: "#fff", cursor: "pointer", fontSize: "11px", display: "flex", gap: "6px", alignItems: "center" }}
                    >
                      {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? "نُسخ" : "نسخ الملف"}
                    </button>
                  </div>
                </div>

                {/* Signals Table */}
                <div style={{ display: "grid", gap: "10px", marginBottom: "18px" }}>
                  {linkReport.signals.map((sig, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: "12px 14px",
                        background: sig.level === "critical" ? "rgba(239,68,68,0.1)" : "rgba(255,255,255,0.03)",
                        borderRight: `3px solid ${sig.level === "critical" ? "#ef4444" : "#d5b76e"}`,
                        borderRadius: "4px",
                      }}
                    >
                      <strong style={{ color: sig.level === "critical" ? "#fca5a5" : "#e5ddc1", fontSize: "13px", display: "block" }}>
                        {sig.title}
                      </strong>
                      <p style={{ margin: "4px 0 0", color: "#93aaa4", fontSize: "11px", lineHeight: "1.6" }}>
                        {sig.detail}
                      </p>
                    </div>
                  ))}
                </div>

                {/* Actionable Mitigations */}
                <div style={{ background: "rgba(5,12,13,0.5)", padding: "14px", borderRadius: "6px", border: "1px solid rgba(210,225,219,0.1)" }}>
                  <span style={{ color: "#d5b76e", fontSize: "11px", fontWeight: "700", display: "block", marginBottom: "8px" }}>
                    خطة التصرف الدفاعي الموصى بها:
                  </span>
                  <ul style={{ margin: 0, paddingRight: "18px", color: "#b8c7c3", fontSize: "11px", lineHeight: "1.7" }}>
                    {linkReport.mitigations.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ================= IMAGE FORENSICS TAB ================= */}
        {activeTab === "image" && (
          <div style={{ display: "grid", gap: "20px" }}>
            <div style={{ background: "rgba(10,18,19,0.9)", padding: "20px", borderRadius: "8px", border: "1px solid rgba(210,225,219,0.14)", textAlign: "center" }}>
              <label
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "10px",
                  padding: "30px",
                  border: "2px dashed rgba(213,183,110,0.35)",
                  borderRadius: "8px",
                  cursor: "pointer",
                  background: "rgba(5,12,13,0.4)",
                }}
              >
                <Camera size={32} color="#d5b76e" />
                <strong style={{ color: "#f0f1eb", fontSize: "14px" }}>اختر صورة للتحليل الجنائي واستخراج بيانات EXIF / ELA</strong>
                <span style={{ color: "#8aa29c", fontSize: "11px" }}>المعالجة تتم بالكامل داخل متصفحك عبر Web Crypto API و Canvas — لا يتم رفع صورتك لأي مكان.</span>
                <input type="file" accept="image/jpeg,image/png,image/webp" onChange={handleImageUpload} style={{ display: "none" }} />
              </label>
              {imageLoading && <p style={{ marginTop: "12px", color: "#d5b76e", fontSize: "12px" }}>جاري قراءة البيانات الوصفية وحساب خريطة تباين الضغط (ELA)...</p>}
            </div>

            {imageError && (
              <div style={{ padding: "12px", background: "rgba(239,68,68,0.15)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: "6px", color: "#fca5a5", fontSize: "12px" }}>
                {imageError}
              </div>
            )}

            {imageReport && (
              <div style={{ background: "linear-gradient(160deg, #122021, #0a1213)", padding: "20px", borderRadius: "8px", border: "1px solid rgba(210,225,219,0.18)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "10px" }}>
                  <div>
                    <span style={{ fontSize: "10px", letterSpacing: "0.1em", color: "#d5b76e", fontWeight: "700" }}>DIGITAL IMAGE FORGERY ANALYSIS (ELA &amp; EXIF)</span>
                    <h4 style={{ margin: "4px 0 0", color: imageReport.tamperingRisk === "high" ? "#ef4444" : "#e5ddc1", fontSize: "17px" }}>
                      {imageReport.tamperingSummary}
                    </h4>
                  </div>
                  <div style={{ display: "flex", gap: "10px" }}>
                    <button
                      onClick={() => setShowEla(!showEla)}
                      style={{ padding: "8px 12px", background: "rgba(255,255,255,0.08)", border: "1px solid rgba(210,225,219,0.2)", borderRadius: "6px", color: "#d5b76e", cursor: "pointer", fontSize: "11px" }}
                    >
                      <Layers size={13} style={{ display: "inline", marginLeft: "4px" }} /> {showEla ? "إخفاء خريطة ELA" : "عرض خريطة ELA"}
                    </button>
                  </div>
                </div>

                {/* ELA Preview Display */}
                {showEla && imageReport.elaCanvasDataUrl && (
                  <div style={{ marginBottom: "18px", padding: "14px", background: "#050b0c", borderRadius: "8px", border: "1px solid rgba(210,225,219,0.15)", textAlign: "center" }}>
                    <span style={{ display: "block", color: "#d5b76e", fontSize: "11px", marginBottom: "8px", fontWeight: "600" }}>
                      خريطة تباين الضغط الجنائي (Error Level Analysis - ELA Map)
                    </span>
                    <img
                      src={imageReport.elaCanvasDataUrl}
                      alt="Error Level Analysis Map"
                      style={{ maxWidth: "100%", maxHeight: "280px", borderRadius: "4px", border: "1px solid rgba(255,255,255,0.1)" }}
                    />
                    <small style={{ display: "block", color: "#7e9791", fontSize: "9px", marginTop: "6px" }}>
                      المناطق ذات السطوع اللوني الشديد أو التباين الحاد تشير إلى مناطق تم تعديلها أو حفظها بمستويات ضغط غير متجانسة مقارنة بباقي الصورة.
                    </small>
                  </div>
                )}

                {/* Technical Metadata Table */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px", marginBottom: "16px" }}>
                  <div style={{ padding: "12px", background: "rgba(255,255,255,0.03)", borderRadius: "6px" }}>
                    <span style={{ color: "#7e9791", fontSize: "10px", display: "block" }}>بصمة التجزئة الرقمية (SHA-256)</span>
                    <code style={{ color: "#a5d6a7", fontSize: "10px", wordBreak: "break-all" }}>{imageReport.sha256}</code>
                  </div>
                  <div style={{ padding: "12px", background: "rgba(255,255,255,0.03)", borderRadius: "6px" }}>
                    <span style={{ color: "#7e9791", fontSize: "10px", display: "block" }}>الأبعاد والحجم</span>
                    <strong style={{ color: "#e5ddc1", fontSize: "12px" }}>
                      {imageReport.dimensions.width} &times; {imageReport.dimensions.height} px ({(imageReport.fileSizeBytes / 1024).toFixed(1)} KB)
                    </strong>
                  </div>
                  <div style={{ padding: "12px", background: "rgba(255,255,255,0.03)", borderRadius: "6px" }}>
                    <span style={{ color: "#7e9791", fontSize: "10px", display: "block" }}>برنامج التحرير / الكاميرا</span>
                    <strong style={{ color: imageReport.exif.software ? "#fca5a5" : "#e5ddc1", fontSize: "12px" }}>
                      {imageReport.exif.software || (imageReport.exif.cameraModel ? `${imageReport.exif.cameraMake || ""} ${imageReport.exif.cameraModel}` : "لا توجد بيانات كاميرا أو برامج تعديل")}
                    </strong>
                  </div>
                  <div style={{ padding: "12px", background: "rgba(255,255,255,0.03)", borderRadius: "6px" }}>
                    <span style={{ color: "#7e9791", fontSize: "10px", display: "block" }}>بيانات الموقع الجغرافي (GPS)</span>
                    <strong style={{ color: imageReport.exif.hasGps ? "#f59e0b" : "#8aa29c", fontSize: "12px" }}>
                      {imageReport.exif.hasGps ? "تم رصد وسوم GPS داخل الصورة" : "لا توجد وسوم GPS في الملف"}
                    </strong>
                  </div>
                </div>

                {/* Signals */}
                {imageReport.tamperingSignals.length > 0 && (
                  <div style={{ background: "rgba(239,68,68,0.08)", padding: "12px", borderRadius: "6px", border: "1px solid rgba(239,68,68,0.2)" }}>
                    <span style={{ color: "#fca5a5", fontSize: "11px", fontWeight: "700", display: "block", marginBottom: "6px" }}>
                      إشارات الفحص الجنائي:
                    </span>
                    <ul style={{ margin: 0, paddingRight: "16px", color: "#fecaca", fontSize: "11px", lineHeight: "1.6" }}>
                      {imageReport.tamperingSignals.map((sig, idx) => (
                        <li key={idx}>{sig}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
