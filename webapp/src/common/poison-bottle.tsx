export function PoisonBottle({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 100 100"
      className={className}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* Bottle body */}
      <path d="M35 30 L35 85 Q35 95 50 95 Q65 95 65 85 L65 30 Z"
        fill="currentColor" opacity="0.15" stroke="currentColor" strokeWidth="2" />
      {/* Neck */}
      <rect x="40" y="15" width="20" height="15" rx="2"
        fill="currentColor" opacity="0.15" stroke="currentColor" strokeWidth="2" />
      {/* Stopper */}
      <rect x="42" y="8" width="16" height="7" rx="2"
        fill="currentColor" opacity="0.3" />
      {/* Skull */}
      <circle cx="50" cy="60" r="10"
        fill="currentColor" opacity="0.4" />
      <circle cx="46" cy="58" r="2" fill="currentColor" opacity="0.6" />
      <circle cx="54" cy="58" r="2" fill="currentColor" opacity="0.6" />
      <path d="M45 65 Q50 69 55 65"
        stroke="currentColor" strokeWidth="1.5" fill="none" opacity="0.6" />
      {/* Crossbones */}
      <line x1="40" y1="52" x2="60" y2="68"
        stroke="currentColor" strokeWidth="1.5" opacity="0.4" />
      <line x1="60" y1="52" x2="40" y2="68"
        stroke="currentColor" strokeWidth="1.5" opacity="0.4" />
      {/* Liquid level */}
      <rect x="37" y="65" width="26" height="18" rx="2"
        fill="currentColor" opacity="0.08" />
      {/* Warning label */}
      <rect x="38" y="70" width="24" height="3" rx="1"
        fill="currentColor" opacity="0.2" />
    </svg>
  );
}
