/**
 * Phoenix Command Center — High-Rigor Local Cyber Defense & Digital Forensics Suite.
 * Local-First, Zero-Cloud, Privacy-by-Design.
 */
import { ThreatForensicsStation } from "@/components/ThreatForensicsStation";
import { EvidenceCapsule, type CapsuleSource } from "@/components/EvidenceCapsule";
import { assessThreatLink, assessVoipCarrier } from "@/lib/threat-engine";
import "@/command-actions.css";
import "@/command-refinement.css";
import jsQR from "jsqr";
import {
  Activity,
  ArrowUpRight,
  Check,
  ChevronLeft,
  CircleAlert,
  ClipboardCheck,
  Copy,
  FileText,
  ImageUp,
  LockKeyhole,
  Network,
  Phone,
  QrCode,
  Radar,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { FormEvent, useMemo, useState } from "react";
import { parsePhoneNumberFromString } from "libphonenumber-js";

type StationId = "threat" | "voip" | "quishing" | "capsule";

type AnalysisResult =
  | { kind: "voip"; score: number; title: string; subtitle: string; points: string[]; response: string[] }
  | { kind: "quishing"; score: number; title: string; subtitle: string; points: string[]; response: string[] };

const commandHero = `${import.meta.env.BASE_URL}assets/phoenix-command-hero.webp`;
const phoenixMark = `${import.meta.env.BASE_URL}assets/phoenix-official-mark.webp`;

const stations: Array<{ id: StationId; label: string; sublabel: string; icon: typeof Phone }> = [
  { id: "threat", label: "التحقيق الجنائي الرقمي", sublabel: "فحص الروابط والصور ELA", icon: ShieldAlert },
  { id: "voip", label: "كاشف احتيال الـ VoIP", sublabel: "فحص الخطوط الافتراضية والوهمية", icon: Phone },
  { id: "quishing", label: "مكافحة Quishing", sublabel: "فحص الروابط المشفرة في QR", icon: QrCode },
  { id: "capsule", label: "كبسولة الأدلة", sublabel: "سجل القضية المشفر محلياً", icon: ClipboardCheck },
];

function band(score: number) {
  if (score >= 65) return { label: "خطر حرج / احتيال محتمل", tone: "danger" };
  if (score >= 35) return { label: "مراجعة مرتفعة", tone: "warning" };
  if (score >= 15) return { label: "تحقق إضافي", tone: "caution" };
  return { label: "إشارات مستقرة", tone: "safe" };
}

function ScoreDial({ score, verified = false }: { score: number; verified?: boolean }) {
  const visualScore = verified ? 100 : score;
  return (
    <div className={`score-dial ${verified ? "score-dial--verified" : ""}`} style={{ "--score": `${visualScore}%` } as React.CSSProperties}>
      <strong>{visualScore}</strong>
      <span>{verified ? "تحقق" : "/ 100"}</span>
    </div>
  );
}

function EmptyReadout() {
  return (
    <div className="empty-readout">
      <div className="scan-orb"><ScanLine size={27} /></div>
      <h3>بانتظار الإشارة.</h3>
      <p>اختر محطة من اليمين، ثم أدخل البيانات أو اختر نموذج فحص لتظهر النتيجة الفورية هنا.</p>
      <div className="empty-readout__grid" aria-hidden="true" />
    </div>
  );
}

export default function Home() {
  const [station, setStation] = useState<StationId>(() => {
    const candidate = new URLSearchParams(window.location.search).get("tool") as StationId | null;
    return candidate && stations.some((item) => item.id === candidate) ? candidate : "threat";
  });
  const [showGuide, setShowGuide] = useState(true);
  const [phoneInput, setPhoneInput] = useState("");
  const [qrStatus, setQrStatus] = useState("اختر صورة QR من جهازك. الفحص يتم محلياً دون فتح الوجهة تلقائياً.");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [notice, setNotice] = useState("");
  const [activity, setActivity] = useState("مركز القيادة جاهز. محطة التحقيق الجنائي نشطة كوضع افتراضي.");
  const [copied, setCopied] = useState(false);

  const currentStation = useMemo(() => stations.find((item) => item.id === station) ?? stations[0], [station]);

  function chooseStation(next: StationId) {
    setStation(next);
    window.history.replaceState({}, "", `${window.location.pathname}?tool=${next}`);
    setNotice("");
    setCopied(false);
    setActivity(`تم تجهيز محطة ${stations.find((item) => item.id === next)?.label ?? "التحليل"}.`);
  }

  // VoIP Carrier Fraud Analyzer
  function readVoip(raw: string) {
    setNotice("");
    const phone = parsePhoneNumberFromString(raw.trim());
    if (!phone || !phone.isPossible() || !phone.isValid()) {
      setResult(null);
      setNotice("أدخل رقماً دولياً صحيحاً يبدأ بـ +، مثل +12025550123 أو +447012345678.");
      return;
    }
    const report = assessVoipCarrier(phone);
    setResult({
      kind: "voip",
      score: report.riskScore,
      title: report.riskVerdict,
      subtitle: `${report.country} · ${report.carrierTypeLabel} · كود الاتصال: ${report.callingCode}`,
      points: [
        `التصنيف الهيكلي للخط: ${report.carrierTypeLabel}`,
        `مستوى الخطورة الجنائية: ${report.riskLevel} (${report.riskScore}/100)`,
        ...report.signals,
      ],
      response: report.recommendations,
    });
    setActivity(`فُحص الرقم عبر كاشف الـ VoIP: تصنيف ${report.carrierType}.`);
  }

  function analyzeVoipSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    readVoip(phoneInput);
  }

  // Quishing (QR Phishing) Analyzer
  function decodeQr(file: File) {
    setNotice("");
    setQrStatus("جاري فك تشفير الـ QR وتحليل الحمولة جنائياً…");
    const objectUrl = URL.createObjectURL(file);
    const image = new Image();
    image.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = image.naturalWidth;
      canvas.height = image.naturalHeight;
      const context = canvas.getContext("2d", { willReadFrequently: true });
      if (!context) {
        setQrStatus("تعذر إنشاء مساحة قراءة للصورة.");
        URL.revokeObjectURL(objectUrl);
        return;
      }
      context.drawImage(image, 0, 0);
      const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
      URL.revokeObjectURL(objectUrl);
      if (!code) {
        setQrStatus("لم يتم العثور على رمز QR صالح في الصورة. جرّب صورة أوضح ومربعة.");
        return;
      }
      const rawPayload = code.data.trim();
      try {
        const threatReport = assessThreatLink(rawPayload);
        setQrStatus("تم فحص حمولة الـ QR وكشف الرابط المخفي بنجاح.");
        setResult({
          kind: "quishing",
          score: threatReport.riskScore,
          title: `Quishing: ${threatReport.riskLabel}`,
          subtitle: `الحمولة المستخرجة: ${threatReport.hostname} · ${threatReport.protocol} · لم يتم الفتح تلقائياً`,
          points: [
            `الرابط المستخرج من QR: ${threatReport.normalizedUrl}`,
            ...threatReport.signals.map((s) => `[تحليل الحمولة] ${s.title}: ${s.detail}`),
          ],
          response: threatReport.mitigations,
        });
        setActivity(`تم فك الـ QR وفحص حمولته ضد هجمات Quishing.`);
      } catch {
        setQrStatus("تمت قراءة محتوى الـ QR محلياً.");
        setResult({
          kind: "quishing",
          score: 0,
          title: "حمولة نصية عادية غير تشعبية",
          subtitle: `نص مقروء محلياً من الـ QR`,
          points: [`المحتوى المقروء: ${rawPayload}`],
          response: ["لم يُفتح المحتوى.", "تأكد من سياق الرسالة قبل نسخ أي تعليمات."],
        });
      }
    };
    image.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      setQrStatus("تعذر تحميل الصورة. اختر ملف PNG أو JPG صالحاً.");
    };
    image.src = objectUrl;
  }

  function runQuickDemo() {
    chooseStation("threat");
    document.getElementById("workspace")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function copyReport() {
    if (!result) return;
    const report = [
      "Phoenix — تقرير الفحص الجنائي",
      `الحالة: ${result.title}`,
      `درجة الخطر: ${result.score}/100`,
      `الملخص: ${result.subtitle}`,
      "الإشارات الجنائية:",
      ...result.points.map((point) => `- ${point}`),
      "بروتوكول التصرف الدفاعي:",
      ...result.response.map((step, index) => `${index + 1}. ${step}`),
      "تم التحليل محلياً 100% داخل المتصفح (Zero-Cloud).",
    ].join("\n");
    await navigator.clipboard.writeText(report);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const safetyBand = result ? band(result.score) : { label: "وضع استعداد", tone: "neutral" };
  const capsuleSource: CapsuleSource | null = result ? { ...result } : null;

  return (
    <div className="command-app" dir="rtl">
      <aside className="command-rail">
        <div className="brand-system">
          <img className="brand-system__mark" src={phoenixMark} alt="رمز Phoenix" />
          <div><strong>Phoenix</strong><span>FORENSICS &amp; THREAT INTELLIGENCE</span></div>
        </div>
        <div className="rail-rule" />
        <nav className="station-nav" aria-label="محطات Phoenix">
          {stations.map(({ id, label, sublabel, icon: Icon }, index) => (
            <button key={id} onClick={() => chooseStation(id)} className={`station-nav__item ${station === id ? "is-active" : ""}`}>
              <span className="station-nav__index">0{index + 1}</span><Icon size={18} /><span><strong>{label}</strong><small>{sublabel}</small></span>
            </button>
          ))}
        </nav>
        <div className="rail-bottom">
          <div><span>المعالجة</span><strong><i /> تعمل محلياً (Zero-Cloud)</strong></div>
          <div><span>الإصدار</span><strong>2026.2 / FORENSICS</strong></div>
        </div>
      </aside>

      <main className="command-main">
        <section className={`command-hero ${station === "threat" ? "" : "command-hero--workbench"}`} style={{ backgroundImage: `linear-gradient(90deg, rgba(5,9,10,.94) 0%, rgba(5,9,10,.76) 38%, rgba(5,9,10,.20) 100%), url(${commandHero})` }}>
          <header className="command-topbar">
            <div className="system-status"><span className="live-dot" /> نظام التحقيق الجنائي المحلي متصل</div>
            <div className="topbar-actions"><button onClick={() => setShowGuide((value) => !value)}><FileText size={15} /> {showGuide ? "إخفاء الدليل" : "دليل الفحص"}</button><span className="timestamp"><ClockLabel /></span></div>
          </header>
          <div className="hero-copy">
            <p className="command-kicker"><Sparkles size={15} /> مركز القيادة والتحقيق الجنائي الرقمي</p>
            <h1>افحص <em>قبل</em> أن تثق.</h1>
            <p>محرك دفاعي محلي لرصد الاحتيال البصري (Homograph)، كشف التلاعب بالصور (ELA)، فحص خطوط الـ VoIP الوهمية، وتوثيق الأدلة الرقمية المشفرة.</p>
            <div className="hero-actions"><button onClick={runQuickDemo}><ScanLine size={17} /> استعراض المحطة الجنائية</button><button onClick={() => setShowGuide(true)}>دليل التشغيل <ChevronLeft size={16} /></button></div>
            <div className="hero-metrics"><span><strong>04</strong> محطات جنائية</span><span><strong>0</strong> بيانات مرفوعة</span><span><strong>100%</strong> معالجة محلية</span></div>
          </div>
          <div className="hero-glass-card"><Radar size={25} /><span>مبدأ التحقيق الجنائي</span><strong>الأدلة الرقمية<br />أقوى من الثقة العمياء.</strong><small>PHX / FORENSIC 01</small></div>
        </section>

        {showGuide && <section className="try-guide"><div className="try-guide__head"><ClipboardCheck size={20} /><div><p>كيف تستخدم محطات التحقيق الجنائي؟</p><span>افحص الروابط المشبوهة، فكك تلاعب الصور، واكشف أرقام الـ VoIP الوهمية دون رفع بياناتك.</span></div><button onClick={() => setShowGuide(false)}>×</button></div><div className="try-guide__steps"><span><b>1</b> اختر المحطة</span><span><b>2</b> أدخل الهدف أو ارفع الملف</span><span><b>3</b> اقرأ إشارات التهديد الجنائية</span><span><b>4</b> صدّر ملف الأدلة المشفر</span></div></section>}

        <section className="command-workspace" id="workspace">
          <div className="workspace-head"><div><p className="command-kicker">المحطة النشطة / {currentStation.label}</p><h2>{station === "threat" ? "التحقيق الجنائي وكشف التهديدات المتقدمة" : station === "voip" ? "كاشف احتيال أرقام الـ VoIP والخطوط الوهمية" : station === "quishing" ? "مختبر مكافحة Quishing واختراق الـ QR" : "كبسولة الأدلة الجنائية المشفرة"}</h2><div className="measurement-strip" aria-hidden="true"><span /><span /><span /><span /><span /><span /><span /><span /></div></div><div className={`safety-chip safety-chip--${station === "capsule" || station === "threat" ? "neutral" : safetyBand.tone}`}><ShieldCheck size={16} /> {station === "threat" ? "تحقيق جنائي رقمي" : station === "capsule" ? "جلسة أدلة محلية" : safetyBand.label}</div></div>
          <div className={`workspace-grid ${station === "capsule" || station === "threat" ? "workspace-grid--capsule" : ""}`}>
            {station === "threat" ? (
              <ThreatForensicsStation onActivity={setActivity} />
            ) : station === "capsule" ? (
              <EvidenceCapsule source={capsuleSource} onActivity={setActivity} />
            ) : (
              <>
                <section className="tool-console">
                  {station === "voip" && (
                    <form onSubmit={analyzeVoipSubmit}>
                      <ToolLabel icon={Phone} label="رقم الهاتف للفحص الجنائي" hint="كشف شبكات الـ VoIP وخطوط التوجيه الوهمية" />
                      <div className="command-input">
                        <span>+ / E.164</span>
                        <input value={phoneInput} onChange={(event) => setPhoneInput(event.target.value)} placeholder="+12025550123 أو +447012345678" dir="ltr" />
                      </div>
                      <div className="tool-actions">
                        <button className="primary-action" type="submit"><ShieldAlert size={17} /> فحص تصنيف الخط</button>
                        <button type="button" className="ghost-action" onClick={() => { const val = "+447012345678"; setPhoneInput(val); readVoip(val); }}>مثال: تحويل احتيالي (+4470)</button>
                        <button type="button" className="ghost-action" onClick={() => { const val = "+18005550199"; setPhoneInput(val); readVoip(val); }}>مثال: رقم مجاني Toll-Free</button>
                      </div>
                    </form>
                  )}

                  {station === "quishing" && (
                    <div>
                      <ToolLabel icon={QrCode} label="صورة رمز QR لفحص Quishing" hint="PNG أو JPG · فك التشفير وفحص الحمولة محلياً" />
                      <label className="qr-dropzone">
                        <ImageUp size={29} />
                        <strong>اختر صورة QR من جهازك لفحص حمولتها الجنائية</strong>
                        <span>{qrStatus}</span>
                        <input type="file" accept="image/png,image/jpeg,image/webp" onChange={(event) => event.target.files?.[0] && decodeQr(event.target.files[0])} />
                      </label>
                      <div className="tool-actions">
                        <button type="button" className="ghost-action" onClick={() => setQrStatus("ارفع أي صورة QR: سيقوم النظام بفك الرابط وفحصه فوراً ضد هجمات التصيد والاحتيال البصري دون فتحه.")}>
                          ما هو هجوم Quishing؟
                        </button>
                      </div>
                    </div>
                  )}

                  {notice && <div className="command-notice"><CircleAlert size={18} /> {notice}</div>}
                  <div className="privacy-line"><LockKeyhole size={14} /> المعالجة محلية بالكامل. لا يتم رفع أي بيانات أو إرسالها لأي خادم.</div>
                </section>

                <section className="readout-panel">
                  <div className="readout-top"><span>READOUT / PHX-{station.toUpperCase()}</span><Activity size={16} /></div>
                  {result ? (
                    <div className="result-readout">
                      <div className="result-summary">
                        <ScoreDial score={result.score} />
                        <div>
                          <p>{result.title}</p>
                          <span>{result.subtitle}</span>
                        </div>
                        <button onClick={copyReport} className="copy-report">
                          {copied ? <Check size={15} /> : <Copy size={15} />} {copied ? "نُسخ" : "نسخ"}
                        </button>
                      </div>
                      <div className="signal-table">
                        <p>الإشارات الجنائية المرصودة</p>
                        {result.points.map((point, index) => (
                          <div key={`${point}-${index}`}>
                            <span>{String(index + 1).padStart(2, "0")}</span>
                            <strong>{point}</strong>
                          </div>
                        ))}
                      </div>
                      <div className="protocol-list">
                        <p><ShieldCheck size={15} /> بروتوكول التصرف الدفاعي الموصى به</p>
                        {result.response.map((step, index) => (
                          <div key={step}>
                            <b>{index + 1}</b>
                            <span>{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <EmptyReadout />
                  )}
                </section>
              </>
            )}
          </div>
        </section>

        <section className="command-footer-grid">
          <div className="command-log"><span className="command-log__label"><Network size={15} /> سجل المركز الجنائي</span><strong>{activity}</strong></div>
          <div className="command-ethics"><span>ميثاق Phoenix الدفاعي</span><p>أداة موجهة حصراً للتحقيق الدفاعي وكشف التهديدات وحماية الضحايا. لا تُستخدم للاختراق الهجومي أو انتهاك الخصوصية.</p></div>
          <button className="scroll-top" onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}><ArrowUpRight size={18} /> أعلى المركز</button>
        </section>
      </main>
    </div>
  );
}

function ToolLabel({ icon: Icon, label, hint }: { icon: typeof Phone; label: string; hint: string }) {
  return (
    <div className="tool-label">
      <span><Icon size={17} /> {label}</span>
      <small>{hint}</small>
    </div>
  );
}

function ClockLabel() {
  const [time] = useState(() => new Intl.DateTimeFormat("ar", { hour: "2-digit", minute: "2-digit", hour12: true }).format(new Date()));
  return <>{time} / LOCAL</>;
}
