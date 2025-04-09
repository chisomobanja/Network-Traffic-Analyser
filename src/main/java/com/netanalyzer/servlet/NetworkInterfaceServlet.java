package com.netanalyzer.servlet;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONArray;
import org.json.JSONObject;
import org.pcap4j.core.PcapNetworkInterface;

import com.netanalyzer.model.PacketCapture;

public class NetworkInterfaceServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        try {
            // Get all network interfaces
            PacketCapture packetCapture = new PacketCapture();
            List<PcapNetworkInterface> devices = packetCapture.findAllDevs();
            
            // Convert to JSON
            JSONArray interfacesArray = new JSONArray();
            for (int i = 0; i < devices.size(); i++) {
                PcapNetworkInterface device = devices.get(i);
                JSONObject interfaceObj = new JSONObject();
                interfaceObj.put("index", i);
                interfaceObj.put("name", device.getName());
                interfaceObj.put("description", device.getDescription());
                interfacesArray.put(interfaceObj);
            }
            
            // Send response
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(interfacesArray.toString());
            
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }
}