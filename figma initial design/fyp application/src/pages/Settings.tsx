import { useState } from "react";

function Toggle({ on, toggle }: { on: boolean; toggle: () => void }) {
  return (
    <button onClick={toggle} className={`relative w-10 h-6 rounded-full transition-colors ${on ? "bg-[#1e3a5f]" : "bg-slate-300"}`}>
      <span className={`absolute top-1 left-1 w-4 h-4 rounded-full bg-white shadow transition-transform ${on ? "translate-x-4" : ""}`} />
    </button>
  );
}

export default function Settings() {
  const [settings, setSettings] = useState({
    blocking: true,
    realtime: true,
    alerts: true,
    emailNotif: false,
  });
  const [saved, setSaved] = useState(false);
  const toggle = (k: keyof typeof settings) => setSettings(s => ({ ...s, [k]: !s[k] }));

  const sections = [
    {
      title: "Security",
      items: [
        { key: "blocking", label: "Website Blocking", desc: "Automatically block malicious websites" },
        { key: "realtime", label: "Real-Time Detection", desc: "Scan URLs in real time as you browse" },
      ],
    },
    {
      title: "Notifications",
      items: [
        { key: "alerts", label: "Security Alerts", desc: "Get notified when a threat is detected" },
        { key: "emailNotif", label: "Email Notifications", desc: "Receive weekly security summary by email" },
      ],
    },
  ];

  return (
    <div className="max-w-xl space-y-5">
      <h2 className="text-xl font-bold text-slate-900">Settings</h2>

      {sections.map(sec => (
        <div key={sec.title} className="bg-white rounded-xl border border-slate-200 p-5">
          <h3 className="font-semibold text-slate-800 mb-4">{sec.title}</h3>
          <div className="divide-y divide-slate-100">
            {sec.items.map(item => (
              <div key={item.key} className="flex items-center justify-between py-3.5">
                <div>
                  <p className="text-sm font-medium text-slate-800">{item.label}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{item.desc}</p>
                </div>
                <Toggle on={settings[item.key as keyof typeof settings]} toggle={() => toggle(item.key as keyof typeof settings)} />
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Privacy */}
      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-800 mb-4">Privacy</h3>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-slate-800">Clear Detection History</p>
            <p className="text-xs text-slate-500 mt-0.5">Remove all scanned URL records from your account</p>
          </div>
          <button className="px-4 py-2 border border-red-300 text-red-600 rounded-lg text-sm font-medium hover:bg-red-50 transition-colors">
            Clear History
          </button>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <button onClick={() => { setSaved(true); setTimeout(() => setSaved(false), 2500); }}
          className="bg-[#1e3a5f] text-white px-6 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors">
          Save Settings
        </button>
        {saved && <span className="text-green-600 text-sm font-medium">✓ Settings saved</span>}
      </div>
    </div>
  );
}
