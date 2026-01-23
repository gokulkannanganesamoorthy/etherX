import { useState, useEffect, useReducer, useRef } from 'react';
import Radar from './components/Radar';
import MetricCard from './components/MetricCard';

// --- Reducer ---
function dataReducer(state, action) {
  switch (action.type) {
    case 'INIT':
      return action.payload;
    case 'NEW_LOG':
      // Prepend new log, keep max 100 for high density
      const newLogs = [action.payload.data, ...(state.logs || [])].slice(
        0,
        100,
      );
      return {
        ...state,
        stats: action.payload.stats,
        logs: newLogs,
        model: state.model,
      };
    default:
      return state;
  }
}

// --- Icons ---
const Icons = {
  Shield: () => (
    <svg
      className="w-4 h-4"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
      />
    </svg>
  ),
  Globe: () => (
    <svg
      className="w-4 h-4"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
      />
    </svg>
  ),
  Alert: () => (
    <svg
      className="w-4 h-4"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
      />
    </svg>
  ),
  Check: () => (
    <svg
      className="w-4 h-4"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M5 13l4 4L19 7"
      />
    </svg>
  ),
};

function App() {
  const [state, dispatch] = useReducer(dataReducer, { stats: {}, logs: [] });
  const [booted, setBooted] = useState(false);
  const [connected, setConnected] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);

  const wsRef = useRef(null);
  const reconnectTimeout = useRef(null);

  // Boot Sequence
  useEffect(() => {
    setTimeout(() => setBooted(true), 1000);
  }, []);

  // Initial Data Fetch
  useEffect(() => {
    fetch('http://localhost:8000/stats')
      .then((res) => res.json())
      .then((data) => dispatch({ type: 'INIT', payload: data }))
      .catch(console.error);
  }, []);

  // WebSocket
  const connect = () => {
    const ws = new WebSocket('ws://localhost:8000/ws');
    ws.onopen = () => setConnected(true);
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'new_log') {
        dispatch({ type: 'NEW_LOG', payload: message });
      }
    };
    ws.onclose = () => {
      setConnected(false);
      reconnectTimeout.current = setTimeout(connect, 3000);
    };
    wsRef.current = ws;
  };
  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, []);

  // Auto-Select newest log if nothing selected
  useEffect(() => {
    if (!selectedLog && state.logs.length > 0) {
      setSelectedLog(state.logs[0]);
    }
  }, [state.logs, selectedLog]);

  if (!booted)
    return (
      <div className="h-screen bg-black text-neon-green flex items-center justify-center font-mono">
        INITIALIZING THREAT INTERFACE...
      </div>
    );

  return (
    <div className="h-screen w-full bg-[#050505] text-[#00ff41] font-mono flex flex-col overflow-hidden">
      {/* TOP BAR / HUD */}
      <header className="h-12 border-b border-[#00ff41]/20 flex items-center justify-between px-4 bg-[#0a0a0a] shrink-0 z-10">
        <div className="flex items-center gap-6">
          <h1 className="text-xl font-bold tracking-widest flex items-center gap-2">
            <Icons.Shield /> ETHERX_SENTINEL{' '}
            <span className="px-1 bg-[#00ff41] text-black text-[10px] rounded-sm">
              PRO
            </span>
          </h1>
          <div className="h-4 w-px bg-[#00ff41]/30"></div>
          <div className="flex gap-4 text-xs opacity-80">
            <div>REQ: {state.stats?.total_requests || 0}</div>
            <div className="text-neon-red">
              BLK: {state.stats?.blocked_requests || 0}
            </div>
            <div className="text-white">
              LAT: {state.logs?.[0]?.latency_ms || 0}ms
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div
            className={`w-2 h-2 rounded-full ${connected ? 'bg-[#00ff41] shadow-[0_0_8px_#00ff41]' : 'bg-red-500 animate-pulse'}`}
          ></div>
          <span className="text-xs font-bold">
            {connected ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>
      </header>

      {/* MAIN CONTENT - SPLIT VIEW */}
      <div className="flex-1 flex overflow-hidden">
        {/* LEFT: HIGH DENSITY GRID (60%) */}
        <div className="w-[60%] border-r border-[#00ff41]/20 flex flex-col bg-black/50">
          {/* Grid Header */}
          <div className="grid grid-cols-12 gap-2 px-4 py-2 border-b border-[#00ff41]/20 text-[10px] font-bold uppercase opacity-60 tracking-wider">
            <div className="col-span-2">Time</div>
            <div className="col-span-2">Method</div>
            <div className="col-span-5">Path</div>
            <div className="col-span-1 text-center">Score</div>
            <div className="col-span-2 text-right">Status</div>
          </div>

          {/* Grid Content */}
          <div className="flex-1 overflow-y-auto custom-scrollbar p-2 space-y-0.5">
            {state.logs.map((log, i) => {
              const isBlocked = log.class === 'blocked';
              const isSelected =
                selectedLog?.time === log.time &&
                selectedLog?.path === log.path;

              return (
                <div
                  key={i}
                  onClick={() => setSelectedLog(log)}
                  className={`
                                    grid grid-cols-12 gap-2 px-3 py-1.5 text-xs border-b border-transparent cursor-pointer transition-colors
                                    ${isSelected ? 'bg-[#00ff41]/10 border-[#00ff41]/30 text-white' : 'hover:bg-[#00ff41]/5 text-[#00ff41]/80'}
                                    ${isBlocked && !isSelected ? 'text-neon-red opacity-100 hover:text-neon-red' : ''}
                                `}
                >
                  <div className="col-span-2 font-mono opacity-70">
                    {log.time}
                  </div>
                  <div
                    className={`col-span-2 font-bold ${log.method === 'GET' ? 'text-blue-400' : 'text-purple-400'}`}
                  >
                    {log.method}
                  </div>
                  <div
                    className="col-span-5 truncate opacity-90"
                    title={log.path}
                  >
                    {log.path}
                  </div>
                  <div
                    className={`col-span-1 text-center font-bold ${log.score > 20 ? 'text-neon-red' : 'text-[#00ff41]'}`}
                  >
                    {Math.floor(log.score)}
                  </div>
                  <div className="col-span-2 text-right font-bold tracking-wider text-[10px]">
                    {isBlocked ? '🚫 BLOCK' : '✅ ALLOW'}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* RIGHT: INSPECTOR PANEL (40%) */}
        <div className="w-[40%] bg-[#0a0a0a] flex flex-col overflow-hidden">
          {selectedLog ? (
            <div className="flex flex-col h-full">
              {/* URL Header */}
              <div className="p-4 border-b border-[#00ff41]/20 bg-black/40">
                <div className="text-[10px] uppercase tracking-widest opacity-50 mb-1">
                  Target Endpoint
                </div>
                <a
                  href={selectedLog.full_url || selectedLog.path}
                  target="_blank"
                  rel="noreferrer"
                  className="text-sm font-bold text-white hover:text-[#00ff41] hover:underline break-all block"
                >
                  {selectedLog.method}{' '}
                  {selectedLog.full_url || selectedLog.path}
                </a>
                <div className="flex gap-4 mt-2 text-[10px]">
                  <span className="bg-[#111] px-2 py-0.5 rounded border border-[#333] text-gray-400">
                    IP: {selectedLog.client_ip}
                  </span>
                  <span className="bg-[#111] px-2 py-0.5 rounded border border-[#333] text-gray-400">
                    Time: {selectedLog.time}
                  </span>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto p-4 space-y-6">
                {/* Visual Risk Indicator */}
                <div
                  className={`p-4 border rounded relative overflow-hidden ${selectedLog.class === 'blocked' ? 'border-neon-red/50 bg-neon-red/5' : 'border-[#00ff41]/30 bg-[#00ff41]/5'}`}
                >
                  <div className="flex justify-between items-center relative z-10">
                    <div>
                      <div className="text-xs uppercase tracking-widest opacity-70">
                        Threat Level
                      </div>
                      <div
                        className={`text-3xl font-black ${selectedLog.class === 'blocked' ? 'text-neon-red' : 'text-[#00ff41]'}`}
                      >
                        {selectedLog.score}{' '}
                        <span className="text-sm font-normal opacity-50">
                          / 100
                        </span>
                      </div>
                    </div>
                    {selectedLog.class === 'blocked' ? (
                      <Icons.Alert />
                    ) : (
                      <Icons.Check />
                    )}
                  </div>
                  {/* Diagonal Stripes BG */}
                  <div
                    className="absolute inset-0 opacity-5"
                    style={{
                      backgroundImage:
                        'linear-gradient(45deg, #000 25%, transparent 25%, transparent 50%, #000 50%, #000 75%, transparent 75%, transparent)',
                      backgroundSize: '10px 10px',
                    }}
                  ></div>
                </div>

                {/* Risk Breakdown */}
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-widest border-b border-[#333] pb-1 mb-2 text-[#00ff41]">
                    Analysis Vector
                  </h3>
                  <div className="space-y-2">
                    {Object.entries(selectedLog.risk_details || {}).map(
                      ([key, val]) => (
                        <div
                          key={key}
                          className="flex justify-between items-center text-xs p-2 bg-[#111] border-l-2 border-[#00ff41]"
                        >
                          <span className="opacity-70 uppercase">
                            {key.replace(/_/g, ' ')}
                          </span>
                          <span className="font-bold text-white">
                            {String(val)}
                          </span>
                        </div>
                      ),
                    )}
                    {(!selectedLog.risk_details ||
                      Object.keys(selectedLog.risk_details).length === 0) && (
                      <div className="text-xs opacity-40 italic">
                        No specific risk triggers found. Traffic is benign.
                      </div>
                    )}
                  </div>
                </div>

                {/* Payload Snippet */}
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-widest border-b border-[#333] pb-1 mb-2 text-[#00ff41]">
                    Payload Snapshot
                  </h3>
                  <div className="bg-black border border-[#333] p-3 text-[10px] font-mono text-gray-400 overflow-x-auto rounded max-h-40 whitespace-pre-wrap">
                    {selectedLog.payload ? (
                      selectedLog.payload
                    ) : (
                      <span className="italic opacity-30">Empty Payload</span>
                    )}
                  </div>
                </div>

                {/* User Agent */}
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-widest border-b border-[#333] pb-1 mb-2 text-[#00ff41]">
                    User Agent
                  </h3>
                  <div className="text-[10px] text-gray-500 break-words font-sans bg-[#111] p-2 rounded">
                    {selectedLog.user_agent || 'Unknown'}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center opacity-30">
              <Icons.Globe />
              <span className="mt-2 text-xs uppercase tracking-widest">
                Awaiting Data Stream...
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
