
import React, { useState, useEffect, useRef } from 'react';
import { Rule, Packet, Action, Protocol, Connection, PacketTraceStep, Incident, ConnectionState } from './types';
import { DEFAULT_RULES, MASTER_CPP_CODE } from './constants';
import { analyzeSecurity, searchGroundingConsultant } from './services/geminiService';
import { GoogleGenAI, Modality } from "@google/genai";

const App: React.FC = () => {
  const [rules, setRules] = useState<Rule[]>(DEFAULT_RULES);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [activeTab, setActiveTab] = useState<'simulation' | 'source' | 'guide'>('simulation');
  
  // Security Module States
  const [spiEnabled, setSpiEnabled] = useState(true);
  const [dpiEnabled, setDpiEnabled] = useState(true);
  const [zeroTrustActive, setZeroTrustActive] = useState(true);
  const [aiBehavioralActive, setAiBehavioralActive] = useState(true);
  
  const [consultantOpen, setConsultantOpen] = useState(false);
  const [consultantQuery, setConsultantQuery] = useState('');
  const [consultantResponse, setConsultantResponse] = useState<{text: string | undefined, sources: any[]} | null>(null);
  const [isConsulting, setIsConsulting] = useState(false);
  const [isCreatingRule, setIsCreatingRule] = useState<boolean>(false);
  const [newAcl, setNewAcl] = useState<Omit<Rule, 'id'>>({ name: '', sourceIp: '0.0.0.0', destIp: 'Host', port: 80, protocol: 'TCP', action: 'ALLOW' });

  const audioContextRef = useRef<AudioContext | null>(null);

  const speakLog = async (text: string) => {
    try {
      if (!audioContextRef.current) {
        audioContextRef.current = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate: 24000 });
      }
      const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
      const response = await ai.models.generateContent({
        model: "gemini-2.5-flash-preview-tts",
        contents: [{ parts: [{ text: `System Alert: ${text}` }] }],
        config: {
          responseModalities: [Modality.AUDIO],
          speechConfig: {
            voiceConfig: { prebuiltVoiceConfig: { voiceName: 'Kore' } },
          },
        },
      });
      const base64Audio = response.candidates?.[0]?.content?.parts?.[0]?.inlineData?.data;
      if (base64Audio) {
        const decodeBase64 = (base64: string) => {
          const binaryString = atob(base64);
          const len = binaryString.length;
          const bytes = new Uint8Array(len);
          for (let i = 0; i < len; i++) bytes[i] = binaryString.charCodeAt(i);
          return bytes;
        };
        const view = decodeBase64(base64Audio);
        const dataInt16 = new Int16Array(view.buffer);
        const buffer = audioContextRef.current.createBuffer(1, dataInt16.length, 24000);
        const channelData = buffer.getChannelData(0);
        for (let i = 0; i < dataInt16.length; i++) channelData[i] = dataInt16[i] / 32768.0;
        const source = audioContextRef.current.createBufferSource();
        source.buffer = buffer;
        source.connect(audioContextRef.current.destination);
        source.start();
      }
    } catch (e) { console.warn("TTS Failed", e); }
  };

  useEffect(() => {
    const timer = setInterval(() => {
      const now = Date.now();
      setConnections(prev => prev.map(c => ({
        ...c,
        throughput: Math.floor(Math.random() * 9000) + 1000 
      })).filter(c => (now - c.lastSeen) < 12000));
    }, 2500);
    return () => clearInterval(timer);
  }, []);

  const handleConsult = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!consultantQuery.trim() || isConsulting) return;
    setIsConsulting(true);
    const result = await searchGroundingConsultant(consultantQuery);
    setConsultantResponse(result);
    setConsultantQuery('');
    setIsConsulting(false);
  };

  const simulatePacket = () => {
    const apps = ['Kernel', 'Web_Server', 'DB_Agent', 'Unknown.bin', 'Discord.exe'];
    const devices = [
      { ip: '192.168.1.50', name: 'Internal LAN Device', type: 'pc' },
      { ip: '198.51.100.100', name: 'External Cloud Host', type: 'cloud' },
      { ip: '127.0.0.1', name: 'Loopback Interface', type: 'host' }
    ];

    const source = devices[Math.floor(Math.random() * devices.length)];
    const targetApp = apps[Math.floor(Math.random() * apps.length)];
    const isMalicious = Math.random() > 0.75;
    const exploitSigs = ["SQL_INJECT", "SHELLCODE_EXEC", "MALWARE_DATA", "XSS_PAYLOAD"];
    const payload = isMalicious ? `EXPLOIT: ${exploitSigs[Math.floor(Math.random() * exploitSigs.length)]}` : "GET /index.html HTTP/1.1 Host: Local";

    const path: PacketTraceStep[] = [
      { label: 'INGRESS', status: 'passed', detail: `Arrived from ${source.ip}` }
    ];

    let action: Action = 'DENY';
    let reason = 'Zero Trust: Default Block';

    // 1. SPI (Stateful Inspection)
    const existing = connections.find(c => c.srcIp === source.ip);
    if (spiEnabled && existing) {
      action = 'ALLOW';
      reason = 'SPI: Matching Established Flow';
      path.push({ label: 'SPI', status: 'passed', detail: `Valid session: ${existing.id}` });
    }

    // 2. Policy Base (ACL)
    if (action === 'DENY') {
      const matched = rules.find(r => (r.sourceIp === '*' || r.sourceIp === source.ip || (r.sourceIp.endsWith('.*') && source.ip.startsWith(r.sourceIp.slice(0,-1)))));
      if (matched) {
        action = matched.action;
        reason = `Policy Enforcement: ${matched.name}`;
        path.push({ label: 'ACL', status: action === 'ALLOW' ? 'passed' : 'blocked', detail: reason });
      }
    }

    // 3. DPI / IPS Module
    if (action === 'ALLOW' && dpiEnabled && isMalicious) {
      action = 'IPS_BLOCK';
      reason = 'IPS: Deep Packet Inspection Block';
      path.push({ label: 'DPI', status: 'alert', detail: 'Signature Match Detected' });
      path.push({ label: 'IPS', status: 'blocked', detail: 'Connection Dropped' });
      
      if (zeroTrustActive) {
        setIncidents(prev => [{
          id: Math.random().toString(36).substring(2, 7),
          timestamp: Date.now(),
          sourceIp: source.ip,
          threatType: 'Exploit Attempt',
          actionTaken: 'ZERO_TRUST_LOCK',
          severity: 'HIGH' as const
        }, ...prev].slice(0, 10));
        speakLog(`Attack blocked from ${source.ip}. Enforcing Zero Trust Lockdown.`);
      }
    }

    // 4. Behavioral AI Analysis
    if (action === 'ALLOW' && aiBehavioralActive && targetApp === 'Kernel' && isMalicious) {
      action = 'ZERO_TRUST_LOCK';
      reason = 'AI: Suspicious Behavioral Anomaly';
      path.push({ label: 'AI_BRAIN', status: 'blocked', detail: 'Pattern mismatch on core system' });
    }

    // Log if allowed
    if (action === 'ALLOW') {
      path.push({ label: 'EGRESS', status: 'passed', detail: `Sent to ${targetApp}` });
      if (!existing) {
        setConnections(prev => [...prev, {
          id: `F-${Math.random().toString(36).substring(2, 6)}`,
          srcIp: source.ip, dstIp: 'Host', srcPort: 51221, dstPort: 80, proto: 'TCP',
          state: 'ESTABLISHED', lastSeen: Date.now(), packetCount: 1, bytesTransferred: 1024, throughput: 2500, app: targetApp
        }]);
      }
    }

    setPackets(prev => [{
      id: Math.random().toString(36).substring(2, 11),
      sourceIp: source.ip, destIp: 'Host', srcPort: 51221, dstPort: 80, protocol: 'TCP' as Protocol,
      payload, timestamp: Date.now(), status: action, reason, evaluationTrace: [reason], visualPath: path
    }, ...prev].slice(0, 15));
  };

  return (
    <div className="min-h-screen bg-[#020617] text-slate-200">
      <header className="border-b border-white/5 bg-slate-900/60 backdrop-blur-3xl px-12 py-7 sticky top-0 z-50 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="bg-gradient-to-tr from-blue-600 to-indigo-600 p-3.5 rounded-2xl shadow-xl shadow-blue-500/20">
            <i className="fas fa-user-shield text-2xl text-white"></i>
          </div>
          <div>
            <h1 className="text-2xl font-black uppercase tracking-tighter italic leading-none">Host <span className="text-blue-500">Guardian</span></h1>
            <p className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.4em] mt-1.5">AI Firewall + IDS/IPS Suite</p>
          </div>
        </div>
        
        <nav className="flex bg-slate-950/50 border border-white/5 rounded-full p-1.5">
          {(['simulation', 'source', 'guide'] as const).map((tab) => (
            <button 
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-10 py-2.5 rounded-full text-[11px] font-black uppercase tracking-widest transition-all ${activeTab === tab ? 'bg-blue-600 text-white shadow-lg scale-105' : 'text-slate-500 hover:text-slate-300'}`}
            >
              {tab}
            </button>
          ))}
        </nav>
        
        <button onClick={() => setConsultantOpen(true)} className="w-12 h-12 rounded-2xl bg-slate-800 border border-white/10 flex items-center justify-center text-blue-400 hover:scale-110 transition-all shadow-lg"><i className="fas fa-robot"></i></button>
      </header>

      <main className="max-w-[1750px] mx-auto p-12">
        {activeTab === 'simulation' && (
          <div className="space-y-12 animate-in fade-in duration-700">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
              {[
                { label: 'Stateful SPI', state: spiEnabled, set: setSpiEnabled, icon: 'fa-stream', color: 'text-blue-400' },
                { label: 'Deep Packet DPI', state: dpiEnabled, set: setDpiEnabled, icon: 'fa-microscope', color: 'text-emerald-400' },
                { label: 'Zero Trust IRS', state: zeroTrustActive, set: setZeroTrustActive, icon: 'fa-lock', color: 'text-indigo-400' },
                { label: 'Behavioral AI', state: aiBehavioralActive, set: setAiBehavioralActive, icon: 'fa-brain', color: 'text-amber-400' }
              ].map((mod, i) => (
                <div key={i} className="bg-slate-900/40 border border-white/5 p-8 rounded-[40px] flex items-center justify-between hover:bg-slate-900/60 transition-all group">
                   <div className="flex items-center gap-6">
                      <div className={`w-14 h-14 rounded-3xl flex items-center justify-center text-xl shadow-lg transition-all ${mod.state ? mod.color + ' bg-white/5 scale-110' : 'text-slate-700 bg-black/20'}`}><i className={`fas ${mod.icon}`}></i></div>
                      <div>
                        <p className="text-[10px] font-black uppercase text-slate-500 tracking-widest leading-none mb-1.5">{mod.label}</p>
                        <button onClick={() => mod.set(!mod.state)} className={`text-xs font-black uppercase ${mod.state ? 'text-white' : 'text-slate-600'}`}>{mod.state ? 'Enabled' : 'Disabled'}</button>
                      </div>
                   </div>
                   <div className={`w-2 h-2 rounded-full ${mod.state ? 'bg-emerald-500 shadow-[0_0_10px_#10b981]' : 'bg-rose-500'} animate-pulse`}></div>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-10">
              <div className="lg:col-span-8 space-y-10">
                 <section className="bg-slate-900/40 border border-white/5 rounded-[50px] overflow-hidden shadow-2xl">
                    <div className="px-10 py-8 border-b border-white/5 bg-white/5 flex justify-between items-center">
                       <div>
                          <h2 className="text-sm font-black uppercase text-blue-400 italic">Host Policy Matrix</h2>
                          <p className="text-[9px] text-slate-600 uppercase font-black tracking-widest mt-1">L3 - L7 Granular Enforcement</p>
                       </div>
                       <button onClick={simulatePacket} className="bg-blue-600 hover:bg-blue-500 text-white px-10 py-3.5 rounded-2xl text-[11px] font-black uppercase tracking-widest shadow-xl shadow-blue-600/30 transition-all active:scale-95">Inject Test Packet</button>
                    </div>
                    <div className="overflow-x-auto p-4">
                       <table className="w-full text-[11px] text-left">
                          <thead>
                            <tr className="bg-slate-950/30 text-slate-500 font-black uppercase border-b border-white/5">
                              <th className="px-8 py-5">Originating Host</th>
                              <th className="px-8 py-5">Target Service</th>
                              <th className="px-8 py-5 text-center">Tech Layer</th>
                              <th className="px-8 py-5 text-right">Policy State</th>
                            </tr>
                          </thead>
                          <tbody>
                            {rules.map(r => (
                              <tr key={r.id} className="border-b border-white/5 hover:bg-white/[0.02] transition-all">
                                <td className="px-8 py-6">
                                   <div className="font-mono text-slate-200 font-bold">{r.sourceIp}</div>
                                   <div className="text-[9px] text-slate-600 font-black uppercase mt-0.5">{r.name}</div>
                                </td>
                                <td className="px-8 py-6 font-mono text-slate-400">PORT:{r.port === 0 ? 'ANY' : r.port} / {r.protocol}</td>
                                <td className="px-8 py-6 text-center text-[9px] font-black text-slate-500 uppercase">SPI + DPI + IRS</td>
                                <td className="px-8 py-6 text-right">
                                   <span className={`px-4 py-1.5 rounded-full text-[10px] font-black ${
                                     r.action === 'ALLOW' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-rose-500/10 text-rose-500'
                                   }`}>{r.action}</span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                       </table>
                    </div>
                 </section>

                 <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                    <section className="bg-slate-900/40 border border-white/5 rounded-[50px] p-8 space-y-6">
                       <h3 className="text-xs font-black uppercase text-blue-400 italic flex items-center gap-3"><i className="fas fa-stream"></i> Active Host Sessions (SPI)</h3>
                       <div className="space-y-4">
                          {connections.map(c => (
                            <div key={c.id} className="bg-slate-950/40 border border-white/10 p-5 rounded-3xl flex items-center justify-between group hover:border-blue-500/30 transition-all">
                               <div>
                                  <p className="text-xs font-black text-slate-300">{c.srcIp}</p>
                                  <p className="text-[10px] text-blue-500 font-black uppercase">{c.app} • ESTABLISHED</p>
                               </div>
                               <div className="text-right">
                                  <p className="text-[10px] font-mono text-slate-500">{c.throughput} bps</p>
                                  <div className="w-20 h-1.5 bg-slate-800 rounded-full mt-2 overflow-hidden"><div className="h-full bg-blue-500 w-2/3"></div></div>
                               </div>
                            </div>
                          ))}
                          {connections.length === 0 && <p className="text-center py-20 text-[10px] uppercase font-black text-slate-700 italic">No Active State Records</p>}
                       </div>
                    </section>
                    <section className="bg-slate-900/40 border border-white/5 rounded-[50px] p-8 space-y-6">
                       <h3 className="text-xs font-black uppercase text-rose-400 italic flex items-center gap-3"><i className="fas fa-biohazard"></i> Automated Threat IRS</h3>
                       <div className="space-y-4">
                          {incidents.map(inc => (
                            <div key={inc.id} className="bg-rose-500/5 border border-rose-500/10 p-5 rounded-3xl animate-pulse">
                               <div className="flex items-center gap-4">
                                  <div className="w-10 h-10 rounded-2xl bg-rose-600 text-white flex items-center justify-center shadow-lg shadow-rose-600/20"><i className="fas fa-lock"></i></div>
                                  <div>
                                     <p className="text-xs font-black text-slate-100">{inc.threatType}</p>
                                     <p className="text-[10px] text-rose-500 font-black uppercase tracking-wider">{inc.actionTaken}</p>
                                  </div>
                               </div>
                            </div>
                          ))}
                          {incidents.length === 0 && <p className="text-center py-20 text-[10px] uppercase font-black text-slate-700 italic">Security Status: Nominal</p>}
                       </div>
                    </section>
                 </div>
              </div>

              <div className="lg:col-span-4 bg-slate-900/40 border border-white/5 rounded-[50px] flex flex-col h-[850px] overflow-hidden shadow-2xl">
                 <div className="px-10 py-9 border-b border-white/5 bg-gradient-to-r from-blue-600/10 to-transparent">
                    <h2 className="text-[11px] font-black uppercase tracking-[0.4em] text-blue-400 italic">DPI Forensic Stream</h2>
                 </div>
                 <div className="flex-1 overflow-y-auto p-10 space-y-8 custom-scrollbar">
                    {packets.map(p => (
                      <div key={p.id} className={`rounded-[45px] border ${p.status === 'ALLOW' ? 'border-emerald-500/10 bg-emerald-500/[0.03]' : 'border-rose-500/10 bg-rose-500/[0.03]'} p-8 space-y-6 group transition-all`}>
                         <div className="flex justify-between items-center">
                            <span className={`text-[10px] font-black uppercase px-4 py-1.5 rounded-full ${p.status === 'ALLOW' ? 'bg-emerald-600 text-white' : 'bg-rose-600 text-white shadow-xl shadow-rose-600/30'}`}>{p.status}</span>
                            <span className="text-[9px] font-mono text-slate-700 uppercase tracking-widest">TRACE_ID_{p.id}</span>
                         </div>
                         <div className="bg-black/50 p-6 rounded-3xl border border-white/5 shadow-inner">
                            <p className="text-[10px] text-slate-600 font-black uppercase mb-2.5">Deep Payload Scan</p>
                            <code className="text-[11px] text-blue-100/70 font-mono italic break-all leading-relaxed">"{p.payload}"</code>
                         </div>
                         <div className="space-y-4">
                            {p.visualPath.map((step, idx) => (
                              <div key={idx} className="flex gap-6">
                                 <div className="flex flex-col items-center">
                                    <div className={`w-5 h-5 rounded-full flex items-center justify-center text-[9px] shadow-lg z-10 ${
                                      step.status === 'passed' ? 'bg-emerald-500' : 
                                      step.status === 'blocked' ? 'bg-rose-600 animate-pulse' : 
                                      step.status === 'alert' ? 'bg-amber-500' : 'bg-slate-700'
                                    }`}>
                                       <i className={`fas ${step.status === 'passed' ? 'fa-check' : 'fa-shield-alt'}`}></i>
                                    </div>
                                    {idx < p.visualPath.length - 1 && <div className="w-0.5 flex-1 bg-slate-800 my-1.5"></div>}
                                 </div>
                                 <div className="pb-2">
                                    <p className="text-[10px] font-black uppercase text-slate-500 tracking-wider mb-0.5">{step.label}</p>
                                    <p className="text-[11px] text-slate-400 font-medium italic">{step.detail}</p>
                                 </div>
                              </div>
                            ))}
                         </div>
                      </div>
                    ))}
                 </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'source' && (
          <div className="animate-in slide-in-from-right duration-500">
             <div className="bg-[#0b0e14] border border-white/5 rounded-[60px] overflow-hidden shadow-2xl">
                <div className="px-14 py-10 border-b border-white/5 bg-white/5 flex justify-between items-center">
                   <div>
                      <span className="text-[11px] font-black uppercase tracking-[0.5em] text-slate-500 italic font-mono leading-none">host_guardian_kernel.cpp</span>
                      <p className="text-[9px] text-slate-700 font-black mt-2 uppercase tracking-[0.2em]">Enterprise Software Protection Suite v4.1</p>
                   </div>
                   <button onClick={() => navigator.clipboard.writeText(MASTER_CPP_CODE)} className="bg-blue-600 hover:bg-blue-500 text-white text-[11px] font-black uppercase px-10 py-3.5 rounded-2xl shadow-xl shadow-blue-600/20">Copy Code</button>
                </div>
                <div className="p-20 max-h-[85vh] overflow-y-auto bg-slate-950/50 custom-scrollbar">
                   <pre className="text-[14px] leading-[2] text-blue-100/60 font-mono italic">{MASTER_CPP_CODE}</pre>
                </div>
             </div>
          </div>
        )}

        {activeTab === 'guide' && (
          <div className="max-w-6xl mx-auto space-y-24 py-12 pb-40 animate-in slide-in-from-bottom-12 duration-1000">
            {/* Guide Header */}
            <div className="text-center space-y-8">
              <div className="inline-block px-6 py-2.5 rounded-full bg-blue-600/10 border border-blue-600/20 text-blue-400 text-[11px] font-black uppercase tracking-[0.4em] mb-4">Manual v4.1 • Deploying Host Guardians</div>
              <h2 className="text-8xl font-black text-white italic tracking-tighter uppercase leading-[0.85]">The Security <br/><span className="text-blue-600">Masterclass</span></h2>
              <p className="text-slate-500 font-bold uppercase tracking-[0.3em] text-xs max-w-3xl mx-auto leading-relaxed">A Complete Practical & Theoretical Framework for C++ Host-Based Protection</p>
              <div className="w-44 h-2.5 bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-600 mx-auto rounded-full mt-12 shadow-[0_0_20px_rgba(37,99,235,0.4)]"></div>
            </div>

            {/* Core Software Definition */}
            <section className="bg-indigo-600/5 border border-indigo-500/10 p-16 rounded-[70px] space-y-12 shadow-2xl">
               <div className="grid grid-cols-1 lg:grid-cols-2 gap-20">
                  <div className="space-y-6">
                     <h3 className="text-3xl font-black uppercase italic text-white tracking-tight">Software vs. Hardware</h3>
                     <p className="text-slate-400 text-sm leading-relaxed">Unlike a perimeter hardware firewall, a <b>Software Firewall</b> is installed directly on a device (host). It provides granular, per-device defense, essential for laptops on public Wi-Fi or preventing <b>Lateral Movement</b> in a corporate environment.</p>
                     <ul className="space-y-4">
                        <li className="flex gap-4 text-sm text-slate-300"><i className="fas fa-check-circle text-blue-500 mt-1"></i> <span><b>Traffic Filtering:</b> Monitors IP/Ports based on local ACLs.</span></li>
                        <li className="flex gap-4 text-sm text-slate-300"><i className="fas fa-check-circle text-blue-500 mt-1"></i> <span><b>App-Level Control:</b> Restrict specific programs from the internet.</span></li>
                        <li className="flex gap-4 text-sm text-slate-300"><i className="fas fa-check-circle text-blue-500 mt-1"></i> <span><b>Zero Trust:</b> Enforces "Least Privilege" for every connection.</span></li>
                     </ul>
                  </div>
                  <div className="bg-black/40 p-10 rounded-[50px] border border-white/5 space-y-8 flex flex-col justify-center">
                     <div className="flex items-center gap-6">
                        <div className="w-16 h-16 rounded-3xl bg-blue-600 flex items-center justify-center text-white text-3xl shadow-xl shadow-blue-600/30"><i className="fas fa-network-wired"></i></div>
                        <div><p className="text-xs font-black text-white uppercase italic">Zero Trust Architecture</p><p className="text-[10px] text-slate-600 uppercase font-bold tracking-widest mt-1">Certified Framework 2026</p></div>
                     </div>
                     <p className="text-xs text-slate-500 leading-relaxed italic">"Always verify, never trust. Every request from the LAN is treated as a potential threat until deep inspection validates the host identity."</p>
                  </div>
               </div>
            </section>

            {/* PHASE 1: HARDWARE */}
            <section className="space-y-12">
              <div className="flex items-center gap-10">
                <div className="w-20 h-20 rounded-[35px] bg-blue-600 flex items-center justify-center text-white font-black text-3xl shadow-2xl shadow-blue-600/30">01</div>
                <h3 className="text-5xl font-black uppercase italic text-white tracking-tighter">Phase 1: Prepare the "Bouncer" (PC-A)</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
                <div className="bg-slate-900/40 border border-white/5 p-14 rounded-[70px] space-y-8 hover:bg-slate-900/60 transition-all border-b-8 border-b-blue-600/40 shadow-xl">
                  <div className="w-16 h-16 rounded-3xl bg-blue-500/10 flex items-center justify-center text-blue-500 text-3xl shadow-lg"><i className="fas fa-microchip"></i></div>
                  <h4 className="text-3xl font-black text-white uppercase italic tracking-tight leading-none">The Kernel Engine</h4>
                  <p className="text-sm text-slate-500 leading-relaxed font-semibold">Turn PC-A into a Security Bridge. It must have a WiFi card and an Ethernet link to the internet.</p>
                  <div className="bg-black/50 p-10 rounded-[40px] border border-white/5 space-y-4">
                    <p className="text-[11px] font-black uppercase text-slate-600 tracking-widest">Install Core Dependencies:</p>
                    <code className="text-blue-400 text-xs block break-all font-mono leading-relaxed bg-black/40 p-5 rounded-2xl">sudo apt update && sudo apt install g++ libpcap-dev build-essential -y</code>
                  </div>
                </div>
                <div className="bg-slate-900/40 border border-white/5 p-14 rounded-[70px] space-y-8 hover:bg-slate-900/60 transition-all border-b-8 border-b-emerald-600/40 shadow-xl">
                  <div className="w-16 h-16 rounded-3xl bg-emerald-500/10 flex items-center justify-center text-emerald-500 text-3xl shadow-lg"><i className="fas fa-wifi"></i></div>
                  <h4 className="text-3xl font-black text-white uppercase italic tracking-tight leading-none">Activate The Radio</h4>
                  <p className="text-sm text-slate-500 leading-relaxed font-semibold">Enable Hotspot mode on PC-A so other devices can join its secure broadcast range.</p>
                  <div className="bg-black/50 p-10 rounded-[40px] border border-white/5 space-y-4">
                    <p className="text-[11px] font-black uppercase text-slate-600 tracking-widest">Install Routing Utilities:</p>
                    <code className="text-emerald-400 text-xs block break-all font-mono leading-relaxed bg-black/40 p-5 rounded-2xl">sudo apt install hostapd dnsmasq -y</code>
                  </div>
                </div>
              </div>
            </section>

            {/* PHASE 2: ROUTING */}
            <section className="space-y-12">
              <div className="flex items-center gap-10">
                <div className="w-20 h-20 rounded-[35px] bg-emerald-600 flex items-center justify-center text-white font-black text-3xl shadow-2xl shadow-emerald-600/30">02</div>
                <h3 className="text-5xl font-black uppercase italic text-white tracking-tighter">Phase 2: Build the Routing Bridge</h3>
              </div>
              <div className="bg-slate-900/40 border border-white/5 p-16 rounded-[80px] space-y-16 shadow-2xl">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-20">
                  <div className="space-y-8">
                    <h5 className="text-sm font-black text-emerald-400 uppercase tracking-[0.3em] flex items-center gap-5">
                      <span className="w-10 h-10 rounded-2xl bg-emerald-400/20 text-emerald-400 flex items-center justify-center text-xs font-black shadow-lg">A</span>
                      Permit Data Forwarding
                    </h5>
                    <p className="text-sm text-slate-400 leading-relaxed">Linux kernels block external transit traffic by default. You must toggle the IP Forwarding bit to allow bytes to cross from the WiFi interface to Ethernet.</p>
                    <div className="bg-black/50 p-10 rounded-[40px] border border-white/5">
                      <code className="text-emerald-400 text-sm font-mono leading-relaxed italic">sudo sysctl -w net.ipv4.ip_forward=1</code>
                    </div>
                  </div>
                  <div className="space-y-8">
                    <h5 className="text-sm font-black text-emerald-400 uppercase tracking-[0.3em] flex items-center gap-5">
                      <span className="w-10 h-10 rounded-2xl bg-emerald-400/20 text-emerald-400 flex items-center justify-center text-xs font-black shadow-lg">B</span>
                      Apply Network Translation (NAT)
                    </h5>
                    <p className="text-sm text-slate-400 leading-relaxed">Mask the internal devices. This ensures responses from the internet can find their way back through PC-A to the correct originating mobile/PC device.</p>
                    <div className="bg-black/50 p-10 rounded-[40px] border border-white/5">
                      <code className="text-emerald-400 text-[11px] block break-all font-mono leading-relaxed italic">sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE</code>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            {/* PHASE 3: THE CODE */}
            <section className="space-y-12">
              <div className="flex items-center gap-10">
                <div className="w-20 h-20 rounded-[35px] bg-rose-600 flex items-center justify-center text-white font-black text-3xl shadow-2xl shadow-rose-600/30">03</div>
                <h3 className="text-5xl font-black uppercase italic text-white tracking-tighter">Phase 3: Launch The C++ Security Brain</h3>
              </div>
              <div className="bg-slate-900/40 border border-white/5 p-16 rounded-[80px] space-y-12 shadow-2xl">
                 <div className="flex flex-col lg:flex-row gap-20">
                    <div className="flex-1 space-y-8">
                       <h4 className="text-3xl font-black text-white uppercase italic tracking-tight">The Forensic Inspector (DPI)</h4>
                       <p className="text-sm text-slate-400 leading-relaxed">Our <b>C++ OOP Guardian</b> hooks into the raw socket. It parses every bit of the payload. If it matches a known attack signature, the <b>IPS</b> terminates the connection immediately.</p>
                       <div className="bg-slate-950/60 p-12 rounded-[50px] border border-white/5 space-y-10 shadow-inner">
                          <div className="flex items-start gap-6">
                             <div className="w-10 h-10 rounded-2xl bg-rose-500/10 text-rose-500 flex items-center justify-center text-xs font-black shrink-0 shadow-lg">1</div>
                             <div className="space-y-2"><p className="text-xs font-black text-white uppercase tracking-widest">Write Source</p><p className="text-[11px] text-slate-600 italic">Copy the code from the <b>SOURCE</b> tab and save it as <code>guardian.cpp</code> on PC-A.</p></div>
                          </div>
                          <div className="flex items-start gap-6">
                             <div className="w-10 h-10 rounded-2xl bg-rose-500/10 text-rose-500 flex items-center justify-center text-xs font-black shrink-0 shadow-lg">2</div>
                             <div className="space-y-2"><p className="text-xs font-black text-white uppercase tracking-widest">Binary Build</p><code className="text-rose-400 text-xs block bg-black/40 p-4 rounded-xl font-mono mt-2">g++ -o fw_guardian guardian.cpp -lpcap</code></div>
                          </div>
                          <div className="flex items-start gap-6">
                             <div className="w-10 h-10 rounded-2xl bg-rose-500/10 text-rose-500 flex items-center justify-center text-xs font-black shrink-0 shadow-lg">3</div>
                             <div className="space-y-2"><p className="text-xs font-black text-white uppercase tracking-widest">Enforce Protection</p><code className="text-rose-400 text-xs block bg-black/40 p-4 rounded-xl font-mono mt-2">sudo ./fw_guardian</code></div>
                          </div>
                       </div>
                    </div>
                    <div className="lg:w-1/3 bg-indigo-600/5 border border-indigo-500/20 rounded-[60px] p-12 flex flex-col items-center justify-center text-center gap-8 shadow-2xl">
                       <div className="w-24 h-24 rounded-full bg-indigo-600 flex items-center justify-center text-4xl text-white shadow-xl animate-pulse"><i className="fas fa-microchip"></i></div>
                       <div className="space-y-3">
                          <h5 className="text-lg font-black text-white uppercase italic leading-none">Kernel Active</h5>
                          <p className="text-[10px] text-slate-600 uppercase font-bold tracking-[0.2em] leading-relaxed">System Monitoring All Mobile & Remote PC Traffic In Real-Time</p>
                       </div>
                       <div className="w-full h-px bg-white/5"></div>
                       <p className="text-[11px] text-slate-500 italic leading-relaxed">The software guardian acts as a "Host Proxy" between the internal network and the open web.</p>
                    </div>
                 </div>
              </div>
            </section>

            {/* PHASE 4: INTEGRATION */}
            <section className="space-y-12">
              <div className="flex items-center gap-10">
                <div className="w-20 h-20 rounded-[35px] bg-indigo-600 flex items-center justify-center text-white font-black text-3xl shadow-2xl shadow-indigo-600/30">04</div>
                <h3 className="text-5xl font-black uppercase italic text-white tracking-tighter">Phase 4: Mobile & Remote Integration</h3>
              </div>
              <div className="bg-slate-900/40 border border-white/5 p-14 rounded-[70px] space-y-12 border-b-8 border-b-indigo-600/40 shadow-xl">
                 <div className="flex flex-col md:flex-row gap-16 items-center">
                    <div className="flex-1 space-y-8">
                       <h4 className="text-3xl font-black text-white uppercase italic tracking-tight">Connect and Inspect</h4>
                       <p className="text-sm text-slate-400 leading-relaxed font-medium">Your PC-A is now a secure broadcast tower. All mobile traffic must travel through your C++ inspection engine to reach the internet.</p>
                       <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                          <div className="bg-slate-950/40 p-10 rounded-[45px] border border-white/5 flex flex-col gap-6 group hover:border-blue-500/50 transition-all">
                             <div className="w-12 h-12 rounded-2xl bg-blue-600/20 text-blue-400 flex items-center justify-center text-lg font-black shadow-lg">1</div>
                             <div className="space-y-2"><p className="text-sm font-black text-white uppercase italic">Mobile Sync</p><p className="text-[11px] text-slate-600 leading-relaxed font-semibold">Join the 'Firewall_Lab' WiFi from your phone. Enter the secure WPA2 passphrase.</p></div>
                          </div>
                          <div className="bg-slate-950/40 p-10 rounded-[45px] border border-white/5 flex flex-col gap-6 group hover:border-emerald-500/50 transition-all">
                             <div className="w-12 h-12 rounded-2xl bg-emerald-600/20 text-emerald-400 flex items-center justify-center text-lg font-black shadow-lg">2</div>
                             <div className="space-y-2"><p className="text-sm font-black text-white uppercase italic">Traffic Audit</p><p className="text-[11px] text-slate-600 leading-relaxed font-semibold">Open a browser on your phone. Observe the PC-A terminal as it logs every packet in real-time.</p></div>
                          </div>
                       </div>
                    </div>
                    <div className="w-full md:w-80 h-96 rounded-[60px] bg-indigo-600/10 border border-indigo-500/20 flex flex-col items-center justify-center gap-10 relative overflow-hidden group shadow-2xl">
                       <div className="absolute inset-0 bg-gradient-to-br from-blue-600/10 to-transparent"></div>
                       <i className="fas fa-mobile-alt text-7xl text-white drop-shadow-2xl group-hover:scale-110 transition-transform"></i>
                       <div className="text-center z-10 px-8">
                          <p className="text-xs font-black text-white uppercase tracking-[0.2em] mb-2">Sync Verified</p>
                          <p className="text-[10px] text-slate-500 font-bold leading-relaxed">PC-to-Mobile Security Tunnel <br/>v4.1 Fully Enforced</p>
                       </div>
                    </div>
                 </div>
              </div>
            </section>

            {/* 2026 Advanced Tech */}
            <section className="space-y-12">
               <div className="flex items-center gap-10">
                 <div className="w-20 h-20 rounded-[35px] bg-amber-600 flex items-center justify-center text-white font-black text-3xl shadow-2xl shadow-amber-600/30">05</div>
                 <h3 className="text-5xl font-black uppercase italic text-white tracking-tighter">Advanced Security Modalities (2026)</h3>
               </div>
               <div className="grid grid-cols-1 md:grid-cols-3 gap-10">
                  <div className="bg-slate-900/40 border border-white/5 p-12 rounded-[60px] space-y-6 hover:bg-slate-900/60 transition-all shadow-xl">
                     <div className="w-14 h-14 rounded-3xl bg-amber-500/10 flex items-center justify-center text-amber-500 text-2xl shadow-lg"><i className="fas fa-brain"></i></div>
                     <h4 className="text-xl font-black text-white uppercase italic">AI Behavioral</h4>
                     <p className="text-xs text-slate-500 leading-relaxed font-semibold italic">Uses machine learning to establish a "normal" traffic baseline. Suddenly suspicious server calls are blocked instantly, even if they match no known signature.</p>
                  </div>
                  <div className="bg-slate-900/40 border border-white/5 p-12 rounded-[60px] space-y-6 hover:bg-slate-900/60 transition-all shadow-xl">
                     <div className="w-14 h-14 rounded-3xl bg-indigo-500/10 flex items-center justify-center text-indigo-500 text-2xl shadow-lg"><i className="fas fa-layer-group"></i></div>
                     <h4 className="text-xl font-black text-white uppercase italic">Container WAF</h4>
                     <p className="text-xs text-slate-500 leading-relaxed font-semibold italic">Specialized Software Firewalls designed for Kubernetes and Docker, monitoring microservice-to-microservice calls in a cloud-native environment.</p>
                  </div>
                  <div className="bg-slate-900/40 border border-white/5 p-12 rounded-[60px] space-y-6 hover:bg-slate-900/60 transition-all shadow-xl">
                     <div className="w-14 h-14 rounded-3xl bg-rose-500/10 flex items-center justify-center text-rose-500 text-2xl shadow-lg"><i className="fas fa-ghost"></i></div>
                     <h4 className="text-xl font-black text-white uppercase italic">Zero Trust Arch</h4>
                     <p className="text-xs text-slate-500 leading-relaxed font-semibold italic">No device is trusted simply because it is "on the network". Every connection request is verified, authorized, and continuously monitored.</p>
                  </div>
               </div>
            </section>
          </div>
        )}
      </main>

      {/* Forensic Advisor Drawer */}
      {consultantOpen && (
        <div className="fixed inset-0 z-[100] flex justify-end">
           <div className="absolute inset-0 bg-slate-950/90 backdrop-blur-md" onClick={() => setConsultantOpen(false)}></div>
           <div className="relative w-full max-w-2xl bg-slate-900 border-l border-white/10 p-16 flex flex-col shadow-2xl">
              <div className="flex justify-between items-center mb-12">
                 <h3 className="text-3xl font-black uppercase italic flex items-center gap-5 tracking-tighter"><i className="fas fa-robot text-blue-500"></i> Cyber <span className="text-blue-500">Advisor</span></h3>
                 <button onClick={() => setConsultantOpen(false)} className="text-slate-500 hover:text-white transition-colors text-2xl"><i className="fas fa-times"></i></button>
              </div>
              <div className="flex-1 overflow-y-auto mb-12 space-y-10 custom-scrollbar pr-4">
                {consultantResponse ? (
                  <div className="space-y-8 animate-in slide-in-from-bottom-4 duration-500">
                    <div className="prose prose-invert prose-p:text-slate-400 text-sm whitespace-pre-wrap leading-relaxed font-medium">{consultantResponse.text}</div>
                    {consultantResponse.sources.length > 0 && (
                      <div className="mt-12 pt-12 border-t border-white/5">
                        <h4 className="text-[11px] font-black uppercase text-slate-600 mb-8 tracking-[0.4em]">Intelligence Sources</h4>
                        <div className="grid grid-cols-1 gap-5">
                          {consultantResponse.sources.map((chunk, idx) => chunk.web && (
                            <a key={idx} href={chunk.web.uri} target="_blank" rel="noopener noreferrer" className="group p-6 rounded-3xl bg-white/[0.03] border border-white/5 hover:border-blue-500/50 transition-all">
                              <div className="text-blue-400 text-xs font-black mb-1">{chunk.web.title}</div>
                              <div className="text-[10px] text-slate-700 truncate font-mono">{chunk.web.uri}</div>
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : isConsulting ? (
                  <div className="h-full flex flex-col items-center justify-center gap-8 opacity-60">
                     <div className="w-16 h-16 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin"></div>
                     <p className="text-[11px] font-black uppercase text-blue-500 tracking-[0.4em] animate-pulse">Syncing Intelligence Database...</p>
                  </div>
                ) : (
                  <div className="text-center py-40 opacity-10">
                    <i className="fas fa-terminal text-9xl mb-10"></i>
                    <p className="font-black uppercase text-xl tracking-[0.5em]">Forensic Scan Ready</p>
                  </div>
                )}
              </div>
              <form onSubmit={handleConsult} className="relative group">
                <input type="text" placeholder="Inquire about zero-trust host defense..." className="w-full bg-slate-950 border border-white/10 p-8 rounded-[32px] text-white pr-24 focus:border-blue-500/50 outline-none transition-all shadow-2xl group-hover:border-white/20" value={consultantQuery} onChange={e => setConsultantQuery(e.target.value)} />
                <button type="submit" className="absolute right-6 top-6 bottom-6 aspect-square bg-blue-600 text-white rounded-2xl shadow-xl shadow-blue-600/30 hover:scale-110 transition-all"><i className="fas fa-paper-plane"></i></button>
              </form>
           </div>
        </div>
      )}

      <footer className="mt-40 py-24 border-t border-white/5 text-center bg-slate-950/40 backdrop-blur-xl">
        <div className="max-w-4xl mx-auto space-y-8 opacity-40 hover:opacity-100 transition-opacity duration-700">
           <p className="text-[11px] text-slate-500 font-black uppercase tracking-[1em]">Enterprise Host Guardian v4.1 & bull; Zero Trust Certified</p>
           <div className="flex justify-center gap-14 text-xs font-black uppercase tracking-widest text-slate-700">
              <span className="hover:text-blue-500 cursor-pointer transition-colors">DPI Engine v9.2</span>
              <span className="hover:text-indigo-500 cursor-pointer transition-colors">Stateful SPI Kernel</span>
              <span className="hover:text-amber-500 cursor-pointer transition-colors">AI-Driven IPS</span>
           </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
