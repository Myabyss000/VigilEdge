// VigilEdge WAF Enhanced Dashboard JavaScript
// Professional Cyber Security Dashboard with Real-time Features

class CyberChart {
    constructor(containerId, type = 'line') {
        this.container = document.getElementById(containerId);
        this.type = type;
        this.data = [];
        this.init();
    }

    init() {
        this.createChart();
        this.setupInteractions();
    }

    createChart() {
        // Create a simple cyber-themed chart visualization
        this.container.innerHTML = '';
        
        const chart = document.createElement('div');
        chart.className = 'cyber-chart';
        chart.style.cssText = `
            width: 100%;
            height: 100%;
            position: relative;
            background: linear-gradient(45deg, rgba(0, 212, 255, 0.05), rgba(0, 255, 166, 0.05));
            border-radius: 8px;
            overflow: hidden;
        `;

        // Add grid lines
        const grid = document.createElement('div');
        grid.className = 'chart-grid';
        grid.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(0, 212, 255, 0.1) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 212, 255, 0.1) 1px, transparent 1px);
            background-size: 20px 20px;
            animation: grid-move 20s linear infinite;
        `;

        // Add sample data visualization
        this.createDataVisualization(chart);
        
        chart.appendChild(grid);
        this.container.appendChild(chart);
    }

    createDataVisualization(container) {
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 2;
        `;

        // Create sample line chart
        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        const points = this.generateSampleData();
        const pathData = this.createPathData(points);
        
        path.setAttribute("d", pathData);
        path.setAttribute("fill", "none");
        path.setAttribute("stroke", "#00d4ff");
        path.setAttribute("stroke-width", "2");
        path.style.filter = "drop-shadow(0 0 5px #00d4ff)";

        // Add animated drawing effect
        const pathLength = path.getTotalLength();
        path.style.strokeDasharray = pathLength;
        path.style.strokeDashoffset = pathLength;
        path.style.animation = "draw-line 3s ease-in-out forwards";

        svg.appendChild(path);
        container.appendChild(svg);
    }

    generateSampleData() {
        const points = [];
        for (let i = 0; i <= 20; i++) {
            const x = (i / 20) * 100;
            const y = 20 + Math.random() * 60 + Math.sin(i * 0.5) * 15;
            points.push({ x, y });
        }
        return points;
    }

    createPathData(points) {
        if (points.length === 0) return "";
        
        let pathData = `M ${points[0].x} ${points[0].y}`;
        for (let i = 1; i < points.length; i++) {
            pathData += ` L ${points[i].x} ${points[i].y}`;
        }
        return pathData;
    }

    setupInteractions() {
        this.container.addEventListener('mouseenter', () => {
            this.container.style.transform = 'scale(1.02)';
            this.container.style.transition = 'transform 0.3s ease';
        });

        this.container.addEventListener('mouseleave', () => {
            this.container.style.transform = 'scale(1)';
        });
    }

    updateData(newData) {
        this.data = newData;
        this.createChart(); // Recreate chart with new data
    }
}

class ThreatMap {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.threats = [];
        this.init();
    }

    init() {
        this.createMap();
        this.simulateThreats();
    }

    createMap() {
        this.container.innerHTML = '';
        
        const map = document.createElement('div');
        map.className = 'threat-map';
        map.style.cssText = `
            width: 100%;
            height: 100%;
            position: relative;
            background: radial-gradient(circle at center, rgba(0, 212, 255, 0.1), rgba(0, 0, 0, 0.3));
            border-radius: 8px;
            overflow: hidden;
        `;

        // Add world map outline (simplified)
        const mapOutline = document.createElement('div');
        mapOutline.style.cssText = `
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 80%;
            height: 60%;
            border: 2px solid rgba(0, 212, 255, 0.3);
            border-radius: 20px;
            background: rgba(0, 212, 255, 0.05);
        `;

        map.appendChild(mapOutline);
        this.container.appendChild(map);
        this.mapElement = map;
    }

    simulateThreats() {
        setInterval(() => {
            this.addThreatMarker();
        }, 3000);
    }

    addThreatMarker() {
        const marker = document.createElement('div');
        marker.className = 'threat-marker';
        
        const x = Math.random() * 80 + 10; // 10% to 90%
        const y = Math.random() * 60 + 20; // 20% to 80%
        
        marker.style.cssText = `
            position: absolute;
            left: ${x}%;
            top: ${y}%;
            width: 12px;
            height: 12px;
            background: #ff3366;
            border-radius: 50%;
            box-shadow: 0 0 15px #ff3366;
            animation: threat-ping 2s ease-out;
            z-index: 3;
        `;

        this.mapElement.appendChild(marker);

        // Remove marker after animation
        setTimeout(() => {
            if (marker.parentNode) {
                marker.parentNode.removeChild(marker);
            }
        }, 2000);
    }
}

class SecurityMetrics {
    constructor() {
        this.metrics = {
            totalRequests: 0,
            blockedThreats: 0,
            activeConnections: 0,
            responseTime: 0
        };
        this.init();
    }

    init() {
        this.startMetricsSimulation();
    }

    startMetricsSimulation() {
        // Simulate real-time metrics updates
        setInterval(() => {
            this.updateMetrics();
        }, 5000);
    }

    updateMetrics() {
        // Simulate realistic metric changes
        this.metrics.totalRequests += Math.floor(Math.random() * 50) + 10;
        this.metrics.blockedThreats += Math.floor(Math.random() * 3);
        this.metrics.activeConnections = Math.floor(Math.random() * 50) + 100;
        this.metrics.responseTime = (Math.random() * 20 + 30).toFixed(1);

        // Update UI
        this.animateMetricUpdate('total-requests', this.metrics.totalRequests);
        this.animateMetricUpdate('blocked-threats', this.metrics.blockedThreats);
        this.animateMetricUpdate('active-connections', this.metrics.activeConnections);
        this.animateMetricUpdate('response-time', this.metrics.responseTime + 'ms');
    }

    animateMetricUpdate(elementId, value) {
        const element = document.getElementById(elementId);
        if (!element) return;

        // Add pulse animation
        element.style.transform = 'scale(1.1)';
        element.style.color = '#00ff66';
        
        setTimeout(() => {
            element.textContent = typeof value === 'number' ? value.toLocaleString() : value;
            element.style.transform = 'scale(1)';
            element.style.color = '';
        }, 200);
    }
}

class NotificationSystem {
    constructor() {
        this.notifications = [];
        this.init();
    }

    init() {
        this.createNotificationContainer();
    }

    createNotificationContainer() {
        if (document.getElementById('notification-container')) return;

        const container = document.createElement('div');
        container.id = 'notification-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            max-width: 400px;
        `;
        document.body.appendChild(container);
    }

    show(message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        
        const colors = {
            info: '#00aaff',
            success: '#00ff66',
            warning: '#ffb347',
            danger: '#ff3366'
        };

        notification.style.cssText = `
            background: rgba(30, 30, 50, 0.95);
            border: 1px solid ${colors[type]};
            border-left: 4px solid ${colors[type]};
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 10px;
            color: white;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), 0 0 20px ${colors[type]}40;
            backdrop-filter: blur(10px);
            transform: translateX(100%);
            transition: transform 0.3s ease;
        `;

        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 1.2em;">${this.getIcon(type)}</span>
                <span>${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" 
                        style="margin-left: auto; background: none; border: none; color: white; cursor: pointer; font-size: 1.2em;">×</button>
            </div>
        `;

        const container = document.getElementById('notification-container');
        container.appendChild(notification);

        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);

        // Auto remove
        if (duration > 0) {
            setTimeout(() => {
                notification.style.transform = 'translateX(100%)';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }, duration);
        }
    }

    getIcon(type) {
        const icons = {
            info: 'ℹ️',
            success: '✅',
            warning: '⚠️',
            danger: '🚨'
        };
        return icons[type] || 'ℹ️';
    }
}

// Initialize dashboard components when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    const trafficChart = new CyberChart('traffic-chart', 'line');
    const geoChart = new ThreatMap('geo-chart');
    
    // Initialize metrics system
    const metrics = new SecurityMetrics();
    
    // Initialize notifications
    const notifications = new NotificationSystem();
    
    // Add some demo notifications
    setTimeout(() => {
        notifications.show('🛡️ Security systems initialized', 'success');
    }, 1000);
    
    setTimeout(() => {
        notifications.show('📊 Real-time monitoring active', 'info');
    }, 2000);

    // Add CSS animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes draw-line {
            to {
                stroke-dashoffset: 0;
            }
        }
        
        @keyframes grid-move {
            0% {
                transform: translate(0, 0);
            }
            100% {
                transform: translate(20px, 20px);
            }
        }
        
        @keyframes threat-ping {
            0% {
                transform: scale(0);
                opacity: 1;
            }
            50% {
                transform: scale(1);
                opacity: 1;
            }
            100% {
                transform: scale(2);
                opacity: 0;
            }
        }
    `;
    document.head.appendChild(style);
});

// Export for global access
window.CyberChart = CyberChart;
window.ThreatMap = ThreatMap;
window.SecurityMetrics = SecurityMetrics;
window.NotificationSystem = NotificationSystem;
