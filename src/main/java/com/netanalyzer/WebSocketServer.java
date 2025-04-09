package com.netanalyzer;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.WebSocketAdapter;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNetworkInterface;

import com.netanalyzer.model.PacketCapture;
import com.netanalyzer.model.TrafficStatistics;
import org.json.JSONObject;

public class WebSocketServer extends WebSocketAdapter {
    private static final Map<Session, CaptureSession> sessions = new ConcurrentHashMap<>();
    private static final PacketCapture packetCapture = new PacketCapture();
    
    @Override
    public void onWebSocketConnect(Session session) {
        super.onWebSocketConnect(session);
        System.out.println("Socket Connected: " + session);
        sessions.put(session, new CaptureSession());
    }
    
    @Override
    public void onWebSocketText(String message) {
        super.onWebSocketText(message);
        System.out.println("Received message: " + message);
        
        try {
            JSONObject json = new JSONObject(message);
            String action = json.getString("action");
            
            if (action.equals("startCapture")) {
                int interfaceIndex = json.getInt("interfaceIndex");
                startCapture(interfaceIndex);
            } else if (action.equals("stopCapture")) {
                stopCapture();
            }
        } catch (Exception e) {
            sendErrorMessage("Error processing message: " + e.getMessage());
        }
    }
    
    @Override
    public void onWebSocketClose(int statusCode, String reason) {
        super.onWebSocketClose(statusCode, reason);
        System.out.println("Socket Closed: [" + statusCode + "] " + reason);
        
        CaptureSession captureSession = sessions.remove(getSession());
        if (captureSession != null) {
            captureSession.cleanup();
        }
    }
    
    @Override
    public void onWebSocketError(Throwable cause) {
        super.onWebSocketError(cause);
        cause.printStackTrace();
    }
    
    private void startCapture(int interfaceIndex) {
        CaptureSession captureSession = sessions.get(getSession());
        if (captureSession == null) return;
        
        try {
            // Get the selected network interface
            PcapNetworkInterface selectedDevice = packetCapture.findAllDevs().get(interfaceIndex);
            
            // Start capture
            captureSession.startCapture(selectedDevice);
            
            // Send success message
            JSONObject response = new JSONObject();
            response.put("type", "captureStarted");
            response.put("interfaceName", selectedDevice.getName());
            sendMessage(response.toString());
            
        } catch (Exception e) {
            sendErrorMessage("Failed to start capture: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void stopCapture() {
        CaptureSession captureSession = sessions.get(getSession());
        if (captureSession == null) return;
        
        captureSession.stopCapture();
        
        // Send success message
        JSONObject response = new JSONObject();
        response.put("type", "captureStopped");
        sendMessage(response.toString());
    }
    
    private void sendErrorMessage(String errorMsg) {
        JSONObject response = new JSONObject();
        response.put("type", "error");
        response.put("message", errorMsg);
        sendMessage(response.toString());
    }
    
    private void sendMessage(String message) {
        try {
            getSession().getRemote().sendString(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Inner class to manage a capture session
    private class CaptureSession {
        private final TrafficStatistics statistics = new TrafficStatistics();
        private ScheduledExecutorService statisticsScheduler;
        
        public void startCapture(PcapNetworkInterface device) throws PcapNativeException, NotOpenException {
            // Stop any existing capture
            stopCapture();
            
            // Reset statistics
            statistics.reset();
            
            // Start packet capture
            packetCapture.startCapture(device, packet -> {
                statistics.processPacket(packet);
            });
            
            // Start statistics updates
            statisticsScheduler = Executors.newSingleThreadScheduledExecutor();
            statisticsScheduler.scheduleAtFixedRate(() -> {
                try {
                    // Prepare statistics data
                    JSONObject statsData = new JSONObject();
                    statsData.put("type", "statistics");
                    statsData.put("totalPackets", statistics.getTotalPackets());
                    statsData.put("packetRate", statistics.getPacketRate());
                    statsData.put("protocols", new JSONObject(statistics.getProtocolCount()));
                    statsData.put("topSources", new JSONObject(statistics.getTopSourceIPs(5)));
                    statsData.put("topDestinations", new JSONObject(statistics.getTopDestinationIPs(5)));
                    statsData.put("anomalyDetected", statistics.detectAnomalies());
                    
                    // Send statistics
                    sendMessage(statsData.toString());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }, 0, 1, TimeUnit.SECONDS);
        }
        
        public void stopCapture() {
            packetCapture.stopCapture();
            
            if (statisticsScheduler != null) {
                statisticsScheduler.shutdown();
                statisticsScheduler = null;
            }
        }
        
        public void cleanup() {
            stopCapture();
        }
    }
}
