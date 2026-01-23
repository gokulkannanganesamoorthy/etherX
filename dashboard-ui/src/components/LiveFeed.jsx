import { useState, useRef, useEffect } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Search,
  StopCircle,
  CheckCircle,
  AlertTriangle,
} from 'lucide-react';

export default function LiveFeed({ logs }) {
  const [filterText, setFilterText] = useState('');
  const [expandedRow, setExpandedRow] = useState(null);
  const bottomRef = useRef(null);

  // Auto-scroll only if not interacting with history to prevent jumping
  useEffect(() => {
    if (!expandedRow) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, expandedRow]);

  const filteredLogs = logs.filter(
    (log) =>
      log.path.toLowerCase().includes(filterText.toLowerCase()) ||
      log.method.includes(filterText.toUpperCase()) ||
      log.class.includes(filterText.toLowerCase()),
  );

  const toggleExpand = (index) => {
    setExpandedRow(expandedRow === index ? null : index);
  };

  if (!logs || logs.length === 0) {
    return (
      <div className="p-4 text-neon-green/30 text-xs text-center font-mono">
        &gt; AWAITING DATA STREAM...
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col font-mono text-xs">
      {/* Filter Bar */}
      <div className="p-2 border-b border-neon-green/20 bg-terminal-dim flex items-center gap-2 sticky top-0 z-20">
        <span className="text-neon-green/50">&gt; SEARCH:</span>
        <input
          type="text"
          className="bg-transparent border-b border-neon-green/30 text-neon-green focus:outline-none focus:border-neon-green w-full"
          placeholder="FILTER BY PATH / METHOD..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
        />
        <div className="px-2 py-0.5 bg-neon-green text-black font-bold text-[10px]">
          {filteredLogs.length} EVENTS
        </div>
      </div>

      {/* Table/List */}
      <div className="flex-1 overflow-y-auto custom-scrollbar p-2">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-terminal-black z-10 text-neon-green/50 border-b border-neon-green/20">
            <tr>
              <th className="p-2 w-8"></th>
              <th className="p-2 w-20">TIME</th>
              <th className="p-2 w-16">MTH</th>
              <th className="p-2">PATH</th>
              <th className="p-2 w-16 text-right">RISK</th>
              <th className="p-2 w-24 text-right">STATUS</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neon-green/10">
            {filteredLogs.map((log, i) => {
              const isBlocked = log.class === 'blocked';
              const isExpanded = expandedRow === i;

              return (
                <>
                  <tr
                    key={i}
                    onClick={() => toggleExpand(i)}
                    className={`
                                    cursor-pointer transition-colors border-l-2 
                                    ${isExpanded ? 'bg-neon-green/10 border-neon-green' : 'border-transparent hover:bg-neon-green/5 hover:border-neon-green/50'}
                                    ${isBlocked ? 'text-neon-red' : 'text-neon-green/80'}
                                `}
                  >
                    <td className="p-2 text-center">
                      {isExpanded ? (
                        <ChevronDown size={10} />
                      ) : (
                        <ChevronRight size={10} />
                      )}
                    </td>
                    <td className="p-2 opacity-70">{log.time}</td>
                    <td className="p-2 font-bold">{log.method}</td>
                    <td className="p-2 truncate max-w-xs">{log.path}</td>
                    <td className="p-2 text-right">{log.score}</td>
                    <td className="p-2 text-right font-bold w-24 flex items-center justify-end gap-1">
                      {isBlocked ? (
                        <AlertTriangle size={10} />
                      ) : (
                        <CheckCircle size={10} />
                      )}
                      {isBlocked ? 'BLOCKED' : 'OK'}
                    </td>
                  </tr>

                  {/* Detailed View */}
                  {isExpanded && (
                    <tr className="bg-terminal-dim/50">
                      <td
                        colSpan="6"
                        className="p-4 border-b border-neon-green/20 text-neon-green/70"
                      >
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <div className="text-[10px] uppercase tracking-widest opacity-50 mb-1">
                              Risk Analysis
                            </div>
                            <div
                              className={`p-2 border ${isBlocked ? 'border-neon-red/50 text-neon-red' : 'border-neon-green/30'} text-xs`}
                            >
                              <div>
                                TYPE:{' '}
                                {isBlocked
                                  ? 'THREAT_DETECTED'
                                  : 'BENIGN_TRAFFIC'}
                              </div>
                              <div>SCORE: {log.score}</div>
                              <div>
                                DETAILS:{' '}
                                {JSON.stringify(log.risk_details || {})}
                              </div>
                            </div>
                          </div>
                          <div>
                            <div className="text-[10px] uppercase tracking-widest opacity-50 mb-1">
                              Request Payload
                            </div>
                            <div className="p-2 bg-black border border-neon-green/20 font-mono text-[10px] text-neon-green whitespace-pre-wrap">
                              {log.method} {log.path} HTTP/1.1
                              <br />
                              Host: 127.0.0.1
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
            <tr ref={bottomRef}></tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
