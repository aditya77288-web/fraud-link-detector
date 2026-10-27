import { MessageSquare, Mail, Send, Smartphone } from 'lucide-react';

export function PlatformTips() {
  const tips = [
    {
      title: 'WhatsApp Links',
      icon: MessageSquare,
      accent: 'text-emerald-400',
      advice: 'Beware of forwarded lottery links, fake customer support accounts, or unexpected verification codes asking you to click an external verification site.',
    },
    {
      title: 'SMS & Smishing',
      icon: Smartphone,
      accent: 'text-blue-400',
      advice: 'Fake missed parcel delivery fees, bank security alerts, or toll payment notices often use misleading URL shorteners or misspelled brand domains.',
    },
    {
      title: 'Telegram Links',
      icon: Send,
      accent: 'text-sky-400',
      advice: 'Watch out for crypto airdrops, bot authorization redirects, or group invites that redirect to unauthorized external login portals.',
    },
    {
      title: 'Email Phishing',
      icon: Mail,
      accent: 'text-purple-400',
      advice: 'Inspect the true destination domain, not just the hyperlinked anchor text. Fake invoice attachments and urgent account warnings are common lures.',
    },
  ];

  return (
    <section aria-labelledby="platform-guidance-heading" className="w-full">
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 sm:p-6">
        <h2 id="platform-guidance-heading" className="text-sm font-semibold text-slate-200 mb-1 flex items-center gap-2">
          Common Red Flags Across Messaging Platforms
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          Phishing attacks often leverage social engineering and urgent messaging to entice immediate clicks.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
          {tips.map((item, idx) => {
            const Icon = item.icon;
            return (
              <div
                key={idx}
                className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5 flex flex-col justify-between"
              >
                <div className="flex items-center gap-2.5 mb-2">
                  <Icon className={`w-4 h-4 ${item.accent}`} aria-hidden="true" />
                  <span className="text-xs font-semibold text-slate-200">{item.title}</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {item.advice}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
