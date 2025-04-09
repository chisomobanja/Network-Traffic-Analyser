package com.netanalyzer.model;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class PacketCapture {

    private PcapHandle handle;
    private Thread captureThread;
    private volatile boolean running;

    public List<PcapNetworkInterface> findAllDevs() {
        List<PcapNetworkInterface> allDevs = new ArrayList<>();
        try {
            allDevs = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            e.printStackTrace();
        }
        return allDevs;
    }

    public void startCapture(PcapNetworkInterface device, Consumer<Packet> packetConsumer) throws PcapNativeException, NotOpenException {
        if (running) {
            return;
        }

        // Setup the packet capture handle
        int snapshotLength = 65536; // Capture entire packet
        int readTimeout = 50; // ms
        int maxPackets = -1; // Unlimited packets
        
        handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        
        running = true;
        
        captureThread = new Thread(() -> {
            try {
                handle.loop(maxPackets, packetConsumer::accept);
            } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                if (running) {
                    e.printStackTrace();
                }
                // Otherwise, the exception is expected (from stopping capture)
            }
        });
        
        captureThread.start();
    }

    public void stopCapture() {
        running = false;
        
        if (handle != null) {
            handle.breakLoop();
            handle.close();
            handle = null;
        }
        
        if (captureThread != null) {
            try {
                captureThread.join(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            captureThread = null;
        }
    }
}