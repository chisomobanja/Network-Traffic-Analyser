package com.netanalyzer.model;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

import java.util.HashMap;
import java.util.Map;

public class PacketAnalyzer {

    public String determineProtocol(Packet packet) {
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            TcpPort srcPort = tcpPacket.getHeader().getSrcPort();
            TcpPort dstPort = tcpPacket.getHeader().getDstPort();
            
            // Check for common protocols based on port numbers
            if (srcPort.valueAsInt() == 80 || dstPort.valueAsInt() == 80) {
                return "HTTP";
            } else if (srcPort.valueAsInt() == 443 || dstPort.valueAsInt() == 443) {
                return "HTTPS";
            } else if (srcPort.valueAsInt() == 22 || dstPort.valueAsInt() == 22) {
                return "SSH";
            } else if (srcPort.valueAsInt() == 21 || dstPort.valueAsInt() == 21) {
                return "FTP";
            } else {
                return "TCP";
            }
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            UdpPort srcPort = udpPacket.getHeader().getSrcPort();
            UdpPort dstPort = udpPacket.getHeader().getDstPort();
            
            if (srcPort.valueAsInt() == 53 || dstPort.valueAsInt() == 53) {
                return "DNS";
            } else if (srcPort.valueAsInt() == 67 || dstPort.valueAsInt() == 67 
                      || srcPort.valueAsInt() == 68 || dstPort.valueAsInt() == 68) {
                return "DHCP";
            } else {
                return "UDP";
            }
        } else if (packet.contains(IcmpV4CommonPacket.class)) {
            return "ICMP";
        } else if (packet.contains(ArpPacket.class)) {
            return "ARP";
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipv6Packet = packet.get(IpV6Packet.class);
            IpNumber nextHeader = ipv6Packet.getHeader().getNextHeader();
            if (nextHeader.equals(IpNumber.ICMPV6)) {
                return "ICMPv6";
            }
            return "IPv6";
        } else if (packet.contains(IpV4Packet.class)) {
            return "IPv4";
        } else {
            return "Other";
        }
    }

    public Map<String, String> extractPacketInfo(Packet packet) {
        Map<String, String> info = new HashMap<>();
        
        // Basic info
        info.put("Size", String.valueOf(packet.length()));
        info.put("Timestamp", String.valueOf(System.currentTimeMillis()));
        
        // Ethernet layer
        if (packet.contains(EthernetPacket.class)) {
            EthernetPacket ethPacket = packet.get(EthernetPacket.class);
            info.put("Source MAC", ethPacket.getHeader().getSrcAddr().toString());
            info.put("Destination MAC", ethPacket.getHeader().getDstAddr().toString());
        }
        
        // IP layer
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
            info.put("Source IP", ipv4Packet.getHeader().getSrcAddr().toString());
            info.put("Destination IP", ipv4Packet.getHeader().getDstAddr().toString());
            info.put("Protocol", ipv4Packet.getHeader().getProtocol().toString());
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipv6Packet = packet.get(IpV6Packet.class);
            info.put("Source IP", ipv6Packet.getHeader().getSrcAddr().toString());
            info.put("Destination IP", ipv6Packet.getHeader().getDstAddr().toString());
            info.put("Next Header", ipv6Packet.getHeader().getNextHeader().toString());
        }
        
        // TCP/UDP layer
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            info.put("Source Port", String.valueOf(tcpPacket.getHeader().getSrcPort().valueAsInt()));
            info.put("Destination Port", String.valueOf(tcpPacket.getHeader().getDstPort().valueAsInt()));
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            info.put("Source Port", String.valueOf(udpPacket.getHeader().getSrcPort().valueAsInt()));
            info.put("Destination Port", String.valueOf(udpPacket.getHeader().getDstPort().valueAsInt()));
        }
        
        return info;
    }
}
