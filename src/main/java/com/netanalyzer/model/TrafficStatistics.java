package com.netanalyzer.model;

import org.pcap4j.packet.Packet;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class TrafficStatistics {

    private final PacketAnalyzer analyzer;
    private final Map<String, Integer> protocolCount;
    private final Map<String, AtomicInteger> sourceIpCount;
    private final Map<String, AtomicInteger> destIpCount;
    private final AtomicLong totalPackets;
    
    private final Queue<Long> packetTimestamps;
    private final int RATE_WINDOW_SIZE = 10; // seconds
    private final int ANOMALY_THRESHOLD = 100; // packets per second
    
    private double baselineRate = 0;
    private int anomalyCounter = 0;

    public TrafficStatistics() {
        analyzer = new PacketAnalyzer();
        protocolCount = new ConcurrentHashMap<>();
        sourceIpCount = new ConcurrentHashMap<>();
        destIpCount = new ConcurrentHashMap<>();
        totalPackets = new AtomicLong(0);
        packetTimestamps = new LinkedList<>();
    }

    public void processPacket(Packet packet) {
        totalPackets.incrementAndGet();
        
        // Record timestamp for rate calculation
        long now = System.currentTimeMillis();
        packetTimestamps.add(now);
        
        // Remove timestamps outside window
        while (!packetTimestamps.isEmpty() && packetTimestamps.peek() < now - (RATE_WINDOW_SIZE * 1000)) {
            packetTimestamps.poll();
        }
        
        // Process protocol
        String protocol = analyzer.determineProtocol(packet);
        protocolCount.put(protocol, protocolCount.getOrDefault(protocol, 0) + 1);
        
        // Extract packet info for IP statistics
        Map<String, String> packetInfo = analyzer.extractPacketInfo(packet);
        
        // Update IP statistics if available
        String srcIp = packetInfo.get("Source IP");
        if (srcIp != null) {
            sourceIpCount.computeIfAbsent(srcIp, k -> new AtomicInteger(0)).incrementAndGet();
        }
        
        String dstIp = packetInfo.get("Destination IP");
        if (dstIp != null) {
            destIpCount.computeIfAbsent(dstIp, k -> new AtomicInteger(0)).incrementAndGet();
        }
        
        // Update baseline rate after some packets
        if (totalPackets.get() == 100) {
            baselineRate = getPacketRate();
        }
    }

    public long getTotalPackets() {
        return totalPackets.get();
    }

    public double getPacketRate() {
        int packetsInWindow = packetTimestamps.size();
        return packetsInWindow / (double) RATE_WINDOW_SIZE;
    }

    public Map<String, Integer> getProtocolCount() {
        return new HashMap<>(protocolCount);
    }

    public Map<String, Integer> getTopSourceIPs(int limit) {
        return getTopEntries(sourceIpCount, limit);
    }

    public Map<String, Integer> getTopDestinationIPs(int limit) {
        return getTopEntries(destIpCount, limit);
    }

    private Map<String, Integer> getTopEntries(Map<String, AtomicInteger> map, int limit) {
        Map<String, Integer> result = new HashMap<>();
        
        map.entrySet().stream()
            .sorted(Map.Entry.<String, AtomicInteger>comparingByValue().reversed())
            .limit(limit)
            .forEach(entry -> result.put(entry.getKey(), entry.getValue().get()));
            
        return result;
    }

    public boolean detectAnomalies() {
        double currentRate = getPacketRate();
        
        // Skip anomaly detection until we have a baseline
        if (baselineRate == 0 || totalPackets.get() < 100) {
            return false;
        }
        
        // Check for sudden spike in traffic
        if (currentRate > baselineRate * 3 || currentRate > ANOMALY_THRESHOLD) {
            anomalyCounter++;
            return anomalyCounter > 2; // Require multiple consecutive detections
        } else {
            anomalyCounter = 0;
            return false;
        }
    }

    public void reset() {
        protocolCount.clear();
        sourceIpCount.clear();
        destIpCount.clear();
        totalPackets.set(0);
        packetTimestamps.clear();
        baselineRate = 0;
        anomalyCounter = 0;
    }
}