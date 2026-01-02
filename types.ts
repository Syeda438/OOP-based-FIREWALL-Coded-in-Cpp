
export type Protocol = 'TCP' | 'UDP' | 'ICMP';
export type Action = 'ALLOW' | 'DENY' | 'IPS_BLOCK' | 'IRS_DYNAMIC_BLOCK' | 'ZERO_TRUST_LOCK';
export type ConnectionState = 'NEW' | 'ESTABLISHED' | 'SYN_SENT' | 'FIN_WAIT' | 'RELATED' | 'INVALID';
export type NatType = 'SNAT' | 'DNAT';

export interface Rule {
  id: string;
  name: string;
  sourceIp: string;
  destIp: string;
  port: number;
  protocol: Protocol;
  action: Action;
  isDynamic?: boolean;
  appControl?: string; // e.g., 'Block File Transfer'
}

export interface Incident {
  id: string;
  timestamp: number;
  sourceIp: string;
  threatType: string;
  actionTaken: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export interface Connection {
  id: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  proto: Protocol;
  state: ConnectionState;
  lastSeen: number;
  packetCount: number;
  bytesTransferred: number;
  throughput: number; 
  app?: string;
}

export interface PacketTraceStep {
  label: string;
  status: 'passed' | 'blocked' | 'transformed' | 'pending' | 'alert' | 'inspected';
  detail: string;
}

export interface Packet {
  id: string;
  sourceIp: string;
  destIp: string;
  srcPort: number;
  dstPort: number;
  protocol: Protocol;
  payload: string;
  timestamp: number;
  status?: Action;
  reason?: string;
  isNatted?: boolean;
  evaluationTrace: string[];
  visualPath: PacketTraceStep[];
}
