export default function MetricCard({ label, value, isAlert }) {
  return (
    <div
      className={`
        relative border flex flex-col justify-between p-4 overflow-hidden group
        ${isAlert ? 'border-neon-red bg-neon-red/10' : 'border-neon-green/30 bg-terminal-dim hover:border-neon-green hover:bg-neon-green/5 transition-colors'}
    `}
    >
      {/* Corner Accents */}
      <div
        className={`absolute top-0 right-0 w-2 h-2 border-t border-r ${isAlert ? 'border-neon-red' : 'border-neon-green'}`}
      ></div>
      <div
        className={`absolute bottom-0 left-0 w-2 h-2 border-b border-l ${isAlert ? 'border-neon-red' : 'border-neon-green'}`}
      ></div>

      <div
        className={`text-[10px] font-bold tracking-widest mb-1 ${isAlert ? 'text-neon-red' : 'text-neon-green/60'}`}
      >
        {label}
      </div>

      <div
        className={`text-3xl font-black tracking-tighter ${isAlert ? 'text-neon-red animate-pulse' : 'text-neon-green'}`}
      >
        {value}
      </div>

      {/* Background Decor */}
      <div className="absolute right-2 bottom-2 opacity-20">
        <div className="flex gap-1">
          <div
            className={`w-1 h-3 ${isAlert ? 'bg-neon-red' : 'bg-neon-green'}`}
          ></div>
          <div
            className={`w-1 h-2 ${isAlert ? 'bg-neon-red' : 'bg-neon-green'}`}
          ></div>
          <div
            className={`w-1 h-4 ${isAlert ? 'bg-neon-red' : 'bg-neon-green'}`}
          ></div>
        </div>
      </div>
    </div>
  );
}
