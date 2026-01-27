import Globe from 'react-globe.gl';
import { useState, useEffect, useRef } from 'react';

export default function ThreatGlobe({ logs }) {
  const globeEl = useRef();
  const [arcs, setArcs] = useState([]);

  useEffect(() => {
    // Auto-rotate
    if (globeEl.current) {
      globeEl.current.controls().autoRotate = true;
      globeEl.current.controls().autoRotateSpeed = 0.5;
    }
  }, []);

  useEffect(() => {
    // Convert new logs to arcs
    // We mock "Source IP" lat/lng for visual effect since we typically just have 127.0.0.1
    // In a real app, we'd use a GeoIP DB.
    const newArcs = (logs || []).slice(0, 10).map((log) => {
      const isBlocked = log.class === 'blocked';
      // Mock start/end points
      const startLat = Math.random() * 180 - 90;
      const startLng = Math.random() * 360 - 180;
      const endLat = 37.7749; // San Francisco (HQ)
      const endLng = -122.4194;

      return {
        startLat,
        startLng,
        endLat,
        endLng,
        color: isBlocked ? ['#ff003c', '#ff003c'] : ['#00ff41', '#00ff41'],
        dashLength: 0.4,
        dashGap: 0.2,
        dashAnimateTime: 2000, // ms
        arcAltitude: 0.3,
        stroke: isBlocked ? 2 : 0.5,
        label: `${log.client_ip} -> ${log.path}`,
      };
    });
    setArcs(newArcs);
  }, [logs]);

  return (
    <div className="w-full h-full flex items-center justify-center relative bg-transparent hover:cursor-grab active:cursor-grabbing">
      <Globe
        ref={globeEl}
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
        backgroundColor="rgba(0,0,0,0)"
        arcsData={arcs}
        arcColor="color"
        arcDashLength="dashLength"
        arcDashGap="dashGap"
        arcDashAnimateTime="dashAnimateTime"
        arcAltitude="arcAltitude"
        arcStroke="stroke"
        atmosphereColor="#00ff41"
        atmosphereAltitude={0.2}
      />
      {/* Holographic Overlay Rings */}
      <div className="absolute inset-0 pointer-events-none border border-[#00ff41]/10 rounded-full animate-pulse-slow"></div>
    </div>
  );
}
