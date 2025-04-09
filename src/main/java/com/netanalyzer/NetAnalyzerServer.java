package com.netanalyzer;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.websocket.server.WebSocketHandler;
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory;

import com.netanalyzer.servlet.NetworkInterfaceServlet;

public class NetAnalyzerServer {
    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {
        // Create and configure server
        Server server = new Server(PORT);
        
        // Setup resource handler for static content
        ResourceHandler resourceHandler = new ResourceHandler();
        resourceHandler.setDirectoriesListed(false);
        resourceHandler.setWelcomeFiles(new String[]{"index.html"});
        // Try to find the webapp directory
        String webappPath = "src/main/webapp";
        if (new java.io.File("webapp").exists()) {
            webappPath = "webapp";
        }
        resourceHandler.setResourceBase(webappPath);
        
        // Setup servlet handler for API endpoints
        ServletContextHandler servletHandler = new ServletContextHandler();
        servletHandler.setContextPath("/api");
        servletHandler.addServlet(new ServletHolder(new NetworkInterfaceServlet()), "/interfaces");
        
        // Setup WebSocket handler
        WebSocketHandler wsHandler = new WebSocketHandler() {
            @Override
            public void configure(WebSocketServletFactory factory) {
                factory.register(WebSocketServer.class);
            }
        };
        
        // Combine handlers
        HandlerList handlers = new HandlerList();
        handlers.addHandler(resourceHandler);
        handlers.addHandler(wsHandler);
        handlers.addHandler(servletHandler);
        server.setHandler(handlers);
        
        // Start server
        System.out.println("Starting Network Traffic Analyzer on port " + PORT);
        server.start();
        System.out.println("Server started successfully");
        System.out.println("Open your browser to http://localhost:" + PORT);
        
        server.join();
    }
}
