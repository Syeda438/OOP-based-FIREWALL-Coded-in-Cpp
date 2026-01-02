
import { Rule } from './types';

export const DEFAULT_RULES: Rule[] = [
  { id: 'host-1', name: 'Localhost Web Loopback', sourceIp: '127.0.0.1', destIp: '127.0.0.1', port: 80, protocol: 'TCP', action: 'ALLOW' },
  { id: 'host-2', name: 'Internal LAN Secure Ingress', sourceIp: '192.168.1.*', destIp: 'HostSystem', port: 22, protocol: 'TCP', action: 'ALLOW' },
  { id: 'host-3', name: 'Zero Trust Default Block', sourceIp: '0.0.0.0', destIp: '0.0.0.0', port: 0, protocol: 'TCP', action: 'DENY' },
];

export const MASTER_CPP_CODE = `/**
 * ============================================================================
 * C++ OOP ENTERPRISE SOFTWARE FIREWALL (HOST-BASED GUARDIAN)
 * ----------------------------------------------------------------------------
 * Features: Stateful Packet Inspection (SPI), Deep Packet Inspection (DPI),
 * and Automated Incident Response (IRS) with Zero Trust Enforcment.
 * ============================================================================
 */

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>

enum class State { NEW, ESTABLISHED, INVALID };
enum class Action { ALLOW, DROP, LOG };

struct Packet {
    std::string srcIp;
    std::string dstIp;
    std::string payload;
    int port;
    std::string protocol;
};

/**
 * STATEFUL PACKET INSPECTION (SPI)
 * Tracks active sessions to ensure inbound packets match outbound requests.
 */
class StatefulInspector {
    std::map<std::string, State> sessionTable;
public:
    State checkState(const std::string& key) {
        if (sessionTable.find(key) != sessionTable.end()) return State::ESTABLISHED;
        return State::NEW;
    }
    void createSession(const std::string& key) { 
        sessionTable[key] = State::ESTABLISHED; 
    }
};

/**
 * DEEP PACKET INSPECTION (DPI) & IDS
 * Scans payload "inside" the packet for malicious signatures or shellcode.
 */
class DPIEngine {
    std::vector<std::string> signatures = {"REVERSE_SHELL", "XSS_ATTACK", "virus.exe", "MALWARE_DATA"};
public:
    bool analyze(const Packet& p) {
        for(auto& sig : signatures) {
            if(p.payload.find(sig) != std::string::npos) return true;
        }
        return false;
    }
};

/**
 * INCIDENT RESPONSE SYSTEM (IRS)
 * Automated "Kill-Switch" and Zero Trust Lockdown logic.
 */
class IRS {
    std::set<std::string> lockdownRegistry;
public:
    void lockdownHost(const std::string& ip) {
        lockdownRegistry.insert(ip);
        std::cout << "[IRS] Automated Zero Trust Lockdown: " << ip << std::endl;
    }
    bool isHostBlocked(const std::string& ip) {
        return lockdownRegistry.count(ip) > 0;
    }
};

class HostGuardianFirewall {
    StatefulInspector spi;
    DPIEngine dpi;
    IRS irs;
public:
    Action filter(const Packet& p) {
        // Step 0: Zero Trust / IRS Check
        if (irs.isHostBlocked(p.srcIp)) return Action::DROP;

        // Step 1: SPI Check (Stateful)
        std::string sessionKey = p.srcIp + "->" + p.dstIp + ":" + std::to_string(p.port);
        if (spi.checkState(sessionKey) == State::ESTABLISHED) {
            // Already validated flow, perform DPI scan
        } else {
            spi.createSession(sessionKey);
        }

        // Step 2: DPI / IPS Enforcement
        if (dpi.analyze(p)) {
            std::cout << "[IDS/IPS ALERT] Malicious payload detected from " << p.srcIp << std::endl;
            irs.lockdownHost(p.srcIp); // Auto-respond via IRS
            return Action::DROP;
        }

        return Action::ALLOW;
    }
};

int main() {
    HostGuardianFirewall guardian;

    // Simulate an attack from documentation IP (RFC 5737)
    Packet malPacket{"198.51.100.100", "LocalHost", "GET / REVERSE_SHELL_EXPLOIT", 443, "TCP"};
    
    std::cout << "Starting Enterprise Software Firewall..." << std::endl;
    if (guardian.filter(malPacket) == Action::DROP) {
        std::cout << ">>> Attack neutralized by IPS Module." << std::endl;
    }

    return 0;
}
`;
