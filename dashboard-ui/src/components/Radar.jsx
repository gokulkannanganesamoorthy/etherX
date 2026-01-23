import { motion } from 'framer-motion';
import { useState, useEffect } from 'react';

export default function Radar({ logs }) {
  // Use recent logs for blips
  // We map IP/Path to Angle to keep the same threat in the same place
  const blips = (logs || []).slice(0, 10).map((log) => {
    // simple hash for angle
    const str = log.client_ip + log.path;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    const angle = Math.abs(hash) % 360;

    // Distance based on recentness (or random for visual spread)
    // Let's use a pseudo-random consistent with the log to keep it stable
    const dist = (Math.abs(hash >> 1) % 40) + 10;

    return {
      id: log.time + log.path, // unique-ish key
      angle: angle,
      dist: dist,
      type: log.class === 'blocked' ? 'threat' : 'safe',
    };
  });

  const isAttack = blips.some((b) => b.type === 'threat');

  return (
    <div className="relative w-full aspect-square flex items-center justify-center overflow-hidden bg-black rounded-full border-4 border-neon-green/50 shadow-[0_0_20px_rgba(0,255,65,0.3)] max-w-[300px] mx-auto">
      {/* Grid: Concentric Circles */}
      <div className="absolute inset-0 rounded-full border border-neon-green/30 opacity-50"></div>
      <div className="absolute inset-8 rounded-full border border-neon-green/30 opacity-50"></div>
      <div className="absolute inset-16 rounded-full border border-neon-green/30 opacity-50"></div>
      <div className="absolute inset-24 rounded-full border border-neon-green/30 opacity-50"></div>

      {/* Grid: Crosshairs */}
      <div className="absolute inset-0 flex items-center justify-center opacity-30">
        <div className="w-full h-px bg-neon-green"></div>
        <div className="h-full w-px bg-neon-green absolute"></div>
      </div>

      {/* Grid: Diagonals */}
      <div className="absolute inset-0 flex items-center justify-center opacity-20 rotate-45">
        <div className="w-full h-px bg-neon-green"></div>
        <div className="h-full w-px bg-neon-green absolute"></div>
      </div>

      {/* Rotating Sector Sweep */}
      <motion.div
        className="absolute w-full h-full rounded-full"
        animate={{ rotate: 360 }}
        transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
        style={{
          background: `conic-gradient(from 0deg, rgba(0, 255, 65, 0.5) 0deg, transparent 60deg)`,
        }}
      />

      {/* Blips */}
      {blips.map((blip, i) => {
        const rad = blip.angle * (Math.PI / 180);
        const x = 50 + blip.dist * Math.cos(rad);
        const y = 50 + blip.dist * Math.sin(rad);

        return (
          <div
            key={i}
            className={`absolute w-3 h-3 rounded-full z-10 blur-[1px] transition-all duration-300 ${blip.type === 'threat' ? 'bg-neon-red shadow-[0_0_10px_#ff003c]' : 'bg-neon-green shadow-[0_0_10px_#00ff41]'}`}
            style={{
              top: `${y}%`,
              left: `${x}%`,
            }}
          />
        );
      })}

      {/* Center Dot */}
      <div className="relative z-10 w-2 h-2 bg-neon-green rounded-full shadow-[0_0_10px_#00ff41]"></div>
    </div>
  );
}
