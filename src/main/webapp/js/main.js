// Handle UI interactions and WebSocket communication
let socket;
let isCapturing = false;

document.addEventListener('DOMContentLoaded', () => {
    // Connect to WebSocket
    initWebSocket();
    
    // Load network interfaces
    loadInterfaces();
    
    // Set up event listeners
    document.getElementById('start-button').addEventListener('click', startCapture);
    document.getElementById('stop-button').addEventListener('click', stopCapture);
});

// Initialize WebSocket connection
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
    const wsUrl = protocol + window.location.host;
    
    socket = new WebSocket(wsUrl);
    
    socket.onopen = function(event) {
        log('Connected to server', 'success');
    };
    
    socket.onclose = function(event) {
        log('Disconnected from server', 'error');
        // Try to reconnect after 5 seconds
        setTimeout(initWebSocket, 5000);
    };
    
    socket.onerror = function(error) {
        log('WebSocket error: ' + error.message, 'error');
    };
    
    socket.onmessage = function(event) {
        const message = JSON.parse(event.data);
        
        switch(message.type) {
            case 'statistics':
                updateStatistics(message);
                break;
            case 'captureStarted':
                log('Packet capture started on ' + message.interfaceName, 'success');
                break;
            case 'captureStopped':
                log('Packet capture stopped', 'warning');
                break;
            case 'error':
                log('Error: ' + message.message, 'error');
                break;
        }
    };
}

// Load available network interfaces
function loadInterfaces() {
    fetch('/api/interfaces')
        .then(response => response.json())
        .then(interfaces => {
            const select = document.getElementById('interface-select');
            
            // Clear existing options
            select.innerHTML = '';
            
            if (interfaces.length === 0) {
                const option = document.createElement('option');
                option.text = 'No interfaces found';
                select.add(option);
                return;
            }
            
            // Add interfaces to dropdown
            interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface.index;
                option.text = iface.name + (iface.description ? ' - ' + iface.description : '');
                select.add(option);
            });
            
            // Enable start button
            document.getElementById('start-button').disabled = false;
            
            log('Found ' + interfaces.length + ' network interfaces', 'success');
        })
        .catch(error => {
            log('Failed to load interfaces: ' + error.message, 'error');
        });
}

// Start packet capture
function startCapture() {
    if (isCapturing) return;
    
    const interfaceSelect = document.getElementById('interface-select');
    const interfaceIndex = interfaceSelect.value;
    
    if (!interfaceIndex) {
        log('Please select a network interface', 'warning');
        return;
    }
    
    // Send start command to server
    const message = {
        action: 'startCapture',
        interfaceIndex: parseInt(interfaceIndex)
    };
    
    socket.send(JSON.stringify(message));
    
    // Update UI
    document.getElementById('start-button').disabled = true;
    document.getElementById('stop-button').disabled = false;
    document.getElementById('interface-select').disabled = true;
    document.getElementById('anomaly-status').textContent = 'Status: Monitoring';
    document.getElementById('anomaly-status').className = 'status-item';
    
    isCapturing = true;
    
    log('Starting packet capture...', 'success');
}

// Stop packet capture
function stopCapture() {
    if (!isCapturing) return;
    
    // Send stop command to server
    const message = {
        action: 'stopCapture'
    };
    
    socket.send(JSON.stringify(message));
    
    // Update UI
    document.getElementById('start-button').disabled = false;
    document.getElementById('stop-button').disabled = true;
    document.getElementById('interface-select').disabled = false;
    document.getElementById('anomaly-status').textContent = 'Status: Idle';
    document.getElementById('anomaly-status').className = 'status-item';
    
    isCapturing = false;
    
    log('Stopping packet capture...', 'warning');
}

// Update statistics display
function updateStatistics(stats) {
    // Update status labels
    document.getElementById('total-packets').textContent = 'Total Packets: ' + stats.totalPackets;
    document.getElementById('packet-rate').textContent = 'Packet Rate: ' + stats.packetRate.toFixed(2) + ' packets/sec';
    
    // Update anomaly status
    if (stats.anomalyDetected) {
        document.getElementById('anomaly-status').textContent = 'Status: ANOMALY DETECTED!';
        document.getElementById('anomaly-status').className = 'status-item danger';
        log('Anomaly detected: Unusual traffic pattern!', 'error');
    } else {
        document.getElementById('anomaly-status').textContent = 'Status: Normal';
        document.getElementById('anomaly-status').className = 'status-item';
    }
    
    // Update charts
    updateTrafficChart(stats.packetRate);
    updateProtocolChart(stats.protocols);
    
    // Update protocol table
    updateProtocolTable(stats.protocols, stats.totalPackets);
    
    // Update source IPs table
    updateTable('sources-table', stats.topSources);
    
    // Update destination IPs table
    updateTable('destinations-table', stats.topDestinations);
}

// Update protocol table
function updateProtocolTable(protocols, totalPackets) {
    const tableBody = document.querySelector('#protocol-table tbody');
    tableBody.innerHTML = '';
    
    Object.entries(protocols).forEach(([protocol, count]) => {
        const row = tableBody.insertRow();
        
        const cellProtocol = row.insertCell(0);
        cellProtocol.textContent = protocol;
        
        const cellCount = row.insertCell(1);
        cellCount.textContent = count;
        
        const cellPercentage = row.insertCell(2);
        const percentage = (count / totalPackets * 100).toFixed(2);
        cellPercentage.textContent = percentage + '%';
    });
}

// Update generic table
function updateTable(tableId, data) {
    const tableBody = document.querySelector('#' + tableId + ' tbody');
    tableBody.innerHTML = '';
    
    Object.entries(data).forEach(([key, value]) => {
        const row = tableBody.insertRow();
        
        const cellKey = row.insertCell(0);
        cellKey.textContent = key;
        
        const cellValue = row.insertCell(1);
        cellValue.textContent = value;
    });
}

// Add entry to log panel
function log(message, type = '') {
    const logPanel = document.getElementById('log-panel');
    const logEntry = document.createElement('div');
    
    logEntry.textContent = getCurrentTime() + ' - ' + message;
    logEntry.className = 'log-entry ' + type;
    
    logPanel.appendChild(logEntry);
    logPanel.scrollTop = logPanel.scrollHeight;
    
    // Keep only the last 100 log entries
    while (logPanel.children.length > 100) {
        logPanel.removeChild(logPanel.firstChild);
    }
}

// Get current time formatted as HH:MM:SS
function getCurrentTime() {
    const now = new Date();
    return now.getHours() + ':' + 
           String(now.getMinutes()).padStart(2, '0') + ':' + 
           String(now.getSeconds()).padStart(2, '0');
}
