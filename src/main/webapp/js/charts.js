// Initialize and manage all charts
let trafficChart;
let protocolChart;
let timeLabels = [];
let trafficData = [];

// Initialize charts when document is loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeTrafficChart();
    initializeProtocolChart();
});

// Initialize the traffic rate line chart
function initializeTrafficChart() {
    const ctx = document.getElementById('traffic-chart').getContext('2d');
    
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timeLabels,
            datasets: [{
                label: 'Packets/sec',
                data: trafficData,
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1,
                fill: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Packets per Second'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    }
                }
            },
            animation: {
                duration: 0
            }
        }
    });
}

// Initialize the protocol distribution pie chart
function initializeProtocolChart() {
    const ctx = document.getElementById('protocol-chart').getContext('2d');
    
    protocolChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    'rgb(255, 99, 132)',
                    'rgb(54, 162, 235)',
                    'rgb(255, 206, 86)',
                    'rgb(75, 192, 192)',
                    'rgb(153, 102, 255)',
                    'rgb(255, 159, 64)',
                    'rgb(199, 199, 199)',
                    'rgb(83, 102, 255)',
                    'rgb(255, 109, 64)',
                    'rgb(159, 199, 199)'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            },
            animation: {
                duration: 0
            }
        }
    });
}

// Update the traffic rate chart with new data
function updateTrafficChart(packetRate) {
    // Add current time as label
    const now = new Date();
    const timeLabel = now.getHours() + ':' + 
                      String(now.getMinutes()).padStart(2, '0') + ':' + 
                      String(now.getSeconds()).padStart(2, '0');
    
    timeLabels.push(timeLabel);
    trafficData.push(packetRate);
    
    // Keep only the last 20 data points
    if (timeLabels.length > 20) {
        timeLabels.shift();
        trafficData.shift();
    }
    
    trafficChart.data.labels = timeLabels;
    trafficChart.data.datasets[0].data = trafficData;
    trafficChart.update();
}

// Update the protocol distribution chart with new data
function updateProtocolChart(protocolData) {
    const labels = Object.keys(protocolData);
    const data = Object.values(protocolData);
    
    protocolChart.data.labels = labels;
    protocolChart.data.datasets[0].data = data;
    protocolChart.update();
}