// ============================================
// VIGILEDGE ATTACK VISUALIZATION DEMO
// Pure client-side educational simulation
// ============================================

class VisualizationDemo {
    constructor() {
        this.canvas = document.getElementById('trafficCanvas');
        this.ctx = this.canvas.getContext('2d');
        this.isRunning = false;
        this.isPresentationMode = false;
        this.presentationIndex = 0;
        this.particles = [];
        this.stats = {
            totalRequests: 0,
            attacksDetected: 0,
            requestsBlocked: 0,
            rateLimited: 0,
            reqPerSec: 0
        };
        
        // Attack configurations
        this.attacks = {
            normal: {
                name: 'Normal Traffic',
                description: 'Regular user requests with no malicious intent',
                color: '#00ff87',
                intensity: 1,
                blockRate: 0
            },
            ddos: {
                name: 'DDoS Attack',
                description: 'Distributed Denial of Service - Overwhelming the server with massive traffic',
                color: '#ff6b6b',
                intensity: 20,
                blockRate: 0.85
            },
            sqli: {
                name: 'SQL Injection',
                description: 'Attempting to inject malicious SQL queries to access/modify database',
                color: '#ff6b6b',
                intensity: 3,
                blockRate: 0.95
            },
            xss: {
                name: 'Cross-Site Scripting (XSS)',
                description: 'Injecting malicious scripts to steal user data or hijack sessions',
                color: '#ff6b6b',
                intensity: 4,
                blockRate: 0.92
            },
            path_traversal: {
                name: 'Path Traversal',
                description: 'Attempting to access restricted directories and files using ../ sequences',
                color: '#ff6b6b',
                intensity: 3,
                blockRate: 0.90
            },
            command_injection: {
                name: 'Command Injection',
                description: 'Trying to execute system commands through vulnerable input fields',
                color: '#ff6b6b',
                intensity: 3,
                blockRate: 0.93
            },
            html_injection: {
                name: 'HTML Injection',
                description: 'Injecting malicious HTML code to modify page content',
                color: '#ff6b6b',
                intensity: 3,
                blockRate: 0.88
            },
            csrf: {
                name: 'Cross-Site Request Forgery',
                description: 'Forging requests from authenticated users without their knowledge',
                color: '#ff6b6b',
                intensity: 2,
                blockRate: 0.94
            },
            rate_limiting: {
                name: 'Rate Limiting',
                description: 'Excessive requests triggering rate limiting protection',
                color: '#ffb347',
                intensity: 10,
                blockRate: 0.70
            }
        };
        
        this.currentAttack = 'normal';
        this.presentationAttacks = ['ddos', 'sqli', 'xss', 'path_traversal', 'command_injection', 'html_injection', 'csrf', 'rate_limiting'];
        
        this.explosions = [];
        this.scanLines = [];
        
        // Perspective mode
        this.currentPerspective = 'all';
        this.perspectiveEffects = {
            attacker: { highlight: 'attacker', dim: ['firewall', 'defender'] },
            defender: { highlight: 'defender', dim: ['attacker', 'firewall'] },
            firewall: { highlight: 'firewall', dim: ['attacker', 'defender'] },
            all: { highlight: 'all', dim: [] }
        };
        
        this.initCanvas();
        this.initChart();
        this.initEventListeners();
        this.startAnimation();
    }
    
    initCanvas() {
        this.resizeCanvas();
        window.addEventListener('resize', () => this.resizeCanvas());
        
        // Positions: Attacker (left), Firewall (center), Target (right)
        this.attackerX = this.canvas.width * 0.15;
        this.attackerY = this.canvas.height / 2;
        this.firewallX = this.canvas.width / 2;
        this.firewallY = this.canvas.height / 2;
        this.targetX = this.canvas.width * 0.85;
        this.targetY = this.canvas.height / 2;
    }
    
    resizeCanvas() {
        const rect = this.canvas.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = rect.height;
        this.attackerX = this.canvas.width * 0.15;
        this.attackerY = this.canvas.height / 2;
        this.firewallX = this.canvas.width / 2;
        this.firewallY = this.canvas.height / 2;
        this.targetX = this.canvas.width * 0.85;
        this.targetY = this.canvas.height / 2;
    }
    
    initChart() {
        const ctx = document.getElementById('trafficChart').getContext('2d');
        this.trafficData = {
            labels: [],
            datasets: [
                {
                    label: 'Normal Traffic',
                    data: [],
                    borderColor: '#00ff87',
                    backgroundColor: 'rgba(0, 255, 135, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Attack Traffic',
                    data: [],
                    borderColor: '#ff6b6b',
                    backgroundColor: 'rgba(255, 107, 107, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Blocked',
                    data: [],
                    borderColor: '#ffb347',
                    backgroundColor: 'rgba(255, 179, 71, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        };
        
        this.chart = new Chart(ctx, {
            type: 'line',
            data: this.trafficData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        labels: {
                            color: '#e1e7f5',
                            font: { size: 11 }
                        }
                    }
                },
                scales: {
                    x: {
                        display: true,
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { color: '#94a3b8', font: { size: 10 } }
                    },
                    y: {
                        display: true,
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { color: '#94a3b8', font: { size: 10 } },
                        beginAtZero: true
                    }
                },
                animation: { duration: 300 }
            }
        });
    }
    
    initEventListeners() {
        // Toggle simulation button
        document.getElementById('toggleSimulation').addEventListener('click', () => {
            this.toggleSimulation();
        });
        
        // Presentation mode button
        document.getElementById('presentationMode').addEventListener('click', () => {
            this.togglePresentationMode();
        });
        
        // Attack type selector
        document.getElementById('attackType').addEventListener('change', (e) => {
            this.currentAttack = e.target.value;
            this.updateAttackDescription();
        });
        
        // Perspective toggle buttons
        document.querySelectorAll('.perspective-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const perspective = e.currentTarget.dataset.perspective;
                this.setPerspective(perspective);
                
                // Update active state
                document.querySelectorAll('.perspective-btn').forEach(b => b.classList.remove('active'));
                e.currentTarget.classList.add('active');
            });
        });
        
        // Reset stats button
        const resetBtn = document.getElementById('resetStats');
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                this.resetStats();
            });
        }
        
        this.updateAttackDescription();
    }
    
    toggleSimulation() {
        this.isRunning = !this.isRunning;
        const btn = document.getElementById('toggleSimulation');
        
        if (this.isRunning) {
            btn.classList.add('active');
            btn.innerHTML = '<span class="btn-icon">⏸️</span><span class="btn-text">Stop Simulation</span>';
            this.addLog('System started', 'success');
        } else {
            btn.classList.remove('active');
            btn.innerHTML = '<span class="btn-icon">▶️</span><span class="btn-text">Start Simulation</span>';
            this.addLog('System stopped', 'info');
            
            // Stop presentation mode if running
            if (this.isPresentationMode) {
                this.togglePresentationMode();
            }
        }
    }
    
    togglePresentationMode() {
        this.isPresentationMode = !this.isPresentationMode;
        const btn = document.getElementById('presentationMode');
        
        if (this.isPresentationMode) {
            btn.classList.add('active');
            btn.innerHTML = '<span class="btn-icon">⏹️</span><span class="btn-text">Stop Presentation</span>';
            this.addLog('Presentation mode activated - Auto-cycling attacks', 'warning');
            
            // Start simulation if not running
            if (!this.isRunning) {
                this.toggleSimulation();
            }
            
            // Start cycling through attacks
            this.presentationIndex = 0;
            this.cycleAttacks();
        } else {
            btn.classList.remove('active');
            btn.innerHTML = '<span class="btn-icon">🎬</span><span class="btn-text">Presentation Mode</span>';
            this.addLog('Presentation mode deactivated', 'info');
            
            if (this.presentationTimer) {
                clearTimeout(this.presentationTimer);
            }
        }
    }
    
    cycleAttacks() {
        if (!this.isPresentationMode) return;
        
        const attack = this.presentationAttacks[this.presentationIndex];
        this.currentAttack = attack;
        document.getElementById('attackType').value = attack;
        this.updateAttackDescription();
        
        this.addLog(`🎬 Presentation: Demonstrating ${this.attacks[attack].name}`, 'warning');
        
        this.presentationIndex = (this.presentationIndex + 1) % this.presentationAttacks.length;
        
        // Cycle every 8 seconds
        this.presentationTimer = setTimeout(() => this.cycleAttacks(), 8000);
    }
    
    updateAttackDescription() {
        const attack = this.attacks[this.currentAttack];
        const desc = document.getElementById('attackDescription');
        desc.textContent = attack.description;
        
        if (this.isRunning) {
            this.addLog(`Attack type changed to: ${attack.name}`, 'info');
        }
    }
    
    setPerspective(perspective) {
        this.currentPerspective = perspective;
        const labels = {
            all: 'All View',
            attacker: 'Attacker Perspective',
            defender: 'Defender Perspective',
            firewall: 'Firewall Perspective'
        };
        
        // Clear existing logs when switching perspective
        const logContainer = document.getElementById('logContainer');
        logContainer.innerHTML = '';
        
        // Update stat labels for new perspective
        this.updateStatLabels();
        this.updateStats();
        
        // Add perspective switch notification
        this.addLog(`Switched to: ${labels[perspective]}`, 'info', 'all');
        
        // Add perspective-specific welcome message
        if (perspective === 'attacker') {
            this.addLog('Viewing from attacker perspective - Monitoring attack attempts', 'warning', 'attacker');
        } else if (perspective === 'firewall') {
            this.addLog('Viewing from firewall perspective - Monitoring security rules', 'info', 'firewall');
        } else if (perspective === 'defender') {
            this.addLog('Viewing from defender perspective - Monitoring protected assets', 'success', 'defender');
        }
    }
    
    resetStats() {
        // Reset all statistics
        this.stats = {
            totalRequests: 0,
            attacksDetected: 0,
            requestsBlocked: 0,
            rateLimited: 0,
            reqPerSec: 0
        };
        
        // Clear all particles
        this.particles = [];
        this.explosions = [];
        
        // Clear chart data
        if (this.chart) {
            this.chart.data.labels = [];
            this.chart.data.datasets[0].data = [];
            this.chart.data.datasets[1].data = [];
            this.chart.data.datasets[2].data = [];
            this.chart.update();
        }
        
        // Clear logs
        const logContainer = document.getElementById('logContainer');
        logContainer.innerHTML = '';
        
        // Update display
        this.updateStatsDisplay();
        
        // Log the reset from all perspectives
        this.addLog('System reset initiated', 'info', 'attacker');
        this.addLog('Statistics and logs cleared', 'success', 'firewall');
        this.addLog('Dashboard reset complete', 'success', 'defender');
    }
    
    createParticle() {
        const attack = this.attacks[this.currentAttack];
        const isAttack = this.currentAttack !== 'normal';
        const isBlocked = isAttack && Math.random() < attack.blockRate;
        
        // Log normal traffic occasionally
        if (!isAttack && Math.random() < 0.05) {
            this.addLog('Sending legitimate HTTP request', 'info', 'attacker');
            this.addLog('Processing normal traffic - All checks passed', 'info', 'firewall');
            this.addLog('Received valid user request', 'success', 'defender');
        }
        
        // Start from attacker area (left side)
        const x = this.attackerX + (Math.random() - 0.5) * 60;
        const y = this.attackerY + (Math.random() - 0.5) * 100;
        
        // First target is firewall, then target server
        let targetX, targetY;
        
        if (isBlocked) {
            // Blocked at firewall
            targetX = this.firewallX;
            targetY = this.firewallY;
        } else {
            // Goes to target server
            targetX = this.targetX;
            targetY = this.targetY;
        }
        
        const particle = {
            x, y,
            targetX, targetY,
            vx: (targetX - x) / 100,
            vy: (targetY - y) / 100,
            color: isAttack ? '#ff6b6b' : '#00ff87',
            isAttack,
            isBlocked,
            size: isAttack ? 6 : 4,
            alpha: 1,
            reachedFirewall: false,
            passedFirewall: false
        };
        
        this.particles.push(particle);
        this.stats.totalRequests++;
        
        if (isAttack) {
            this.stats.attacksDetected++;
            if (isBlocked) {
                this.stats.requestsBlocked++;
                this.logAttackBlocked();
            }
        }
        
        if (this.currentAttack === 'rate_limiting' && isBlocked) {
            this.stats.rateLimited++;
        }
    }
    
    logAttackBlocked() {
        const attack = this.attacks[this.currentAttack];
        
        // Attacker perspective messages
        const attackerMessages = {
            ddos: 'Launching flood of requests to overwhelm target',
            sqli: 'Injecting SQL payload: \' OR 1=1 --',
            xss: 'Attempting to inject <script> payload',
            path_traversal: 'Probing for ../../etc/passwd access',
            command_injection: 'Sending system command payload: ; rm -rf /',
            html_injection: 'Injecting malicious HTML content',
            csrf: 'Forging authenticated user request',
            rate_limiting: 'Sending rapid burst of requests'
        };
        
        // Firewall perspective messages
        const firewallMessages = {
            ddos: '🚫 Anomaly detected - Traffic spike blocked',
            sqli: '🛡️ SQL injection pattern matched - Request denied',
            xss: '🔒 Script tag detected - Payload sanitized',
            path_traversal: '⚠️ Directory traversal blocked - Rule #4201',
            command_injection: '🚨 Shell command detected - Blocked by WAF',
            html_injection: '✅ Malicious HTML filtered - Request cleaned',
            csrf: '🔐 CSRF validation failed - Token mismatch',
            rate_limiting: '⏱️ Rate threshold exceeded - Client throttled'
        };
        
        // Defender perspective messages
        const defenderMessages = {
            ddos: '✅ Protected from DDoS flood - Firewall active',
            sqli: '✅ Database secure - Injection attempt blocked',
            xss: '✅ User data protected - Script filtered',
            path_traversal: '✅ File system secure - Access denied',
            command_injection: '✅ System protected - Command blocked',
            html_injection: '✅ Content integrity maintained',
            csrf: '✅ Session protected - Forged request rejected',
            rate_limiting: '✅ Service stable - Flood prevented'
        };
        
        if (Math.random() < 0.3) {
            // Log from attacker perspective
            this.addLog(attackerMessages[this.currentAttack], 'warning', 'attacker');
            
            // Log from firewall perspective
            this.addLog(firewallMessages[this.currentAttack], 'danger', 'firewall');
            
            // Log from defender perspective
            this.addLog(defenderMessages[this.currentAttack], 'success', 'defender');
        }
    }
    
    updateParticles() {
        for (let i = this.particles.length - 1; i >= 0; i--) {
            const p = this.particles[i];
            
            // Move towards target
            p.x += p.vx;
            p.y += p.vy;
            
            // Check distance to firewall
            const distToFirewall = Math.hypot(p.x - this.firewallX, p.y - this.firewallY);
            
            // Check distance to final target
            const distToTarget = Math.hypot(p.x - this.targetX, p.y - this.targetY);
            
            if (distToFirewall < 50 && !p.reachedFirewall) {
                p.reachedFirewall = true;
                
                if (p.isBlocked) {
                    // BLOCKED - Create explosion and bounce back (STAY RED)
                    this.createExplosion(p.x, p.y, '#ff6b6b');
                    
                    // Bounce back toward attacker
                    const angleBack = Math.atan2(this.attackerY - p.y, this.attackerX - p.x);
                    p.vx = Math.cos(angleBack) * 3;
                    p.vy = Math.sin(angleBack) * 3;
                } else {
                    // ALLOWED - Continue to target server (TURN GREEN)
                    p.passedFirewall = true;
                    p.color = '#00ff87'; // Change to green after passing firewall
                    const angleToTarget = Math.atan2(this.targetY - p.y, this.targetX - p.x);
                    p.vx = Math.cos(angleToTarget) * 2;
                    p.vy = Math.sin(angleToTarget) * 2;
                }
            }
            
            // Reached target server (allowed traffic)
            if (!p.isBlocked && p.passedFirewall && distToTarget < 30) {
                p.alpha -= 0.05;
            }
            
            // Fade out blocked particles going back
            if (p.isBlocked && p.reachedFirewall) {
                p.alpha -= 0.02;
            }
            
            // Remove if faded or out of bounds
            if (p.alpha <= 0 || p.x < -50 || p.x > this.canvas.width + 50 || p.y < -50 || p.y > this.canvas.height + 50) {
                this.particles.splice(i, 1);
            }
        }
    }
    
    drawParticles() {
        this.particles.forEach(p => {
            this.ctx.save();
            this.ctx.globalAlpha = p.alpha;
            
            // Draw motion trail
            const trailLength = 8;
            for (let i = 0; i < trailLength; i++) {
                const trailAlpha = p.alpha * (1 - i / trailLength) * 0.4;
                this.ctx.globalAlpha = trailAlpha;
                this.ctx.beginPath();
                this.ctx.arc(
                    p.x - p.vx * i * 3, 
                    p.y - p.vy * i * 3, 
                    p.size * (1 - i / trailLength * 0.5), 
                    0, 
                    Math.PI * 2
                );
                this.ctx.fillStyle = p.color;
                this.ctx.fill();
            }
            
            // Draw main particle with enhanced glow
            this.ctx.globalAlpha = p.alpha;
            this.ctx.beginPath();
            this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            
            // Create radial gradient for particle
            const gradient = this.ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.size * 2);
            gradient.addColorStop(0, p.color);
            gradient.addColorStop(0.5, p.color);
            gradient.addColorStop(1, 'transparent');
            this.ctx.fillStyle = gradient;
            this.ctx.fill();
            
            // Enhanced glow
            this.ctx.shadowBlur = 25;
            this.ctx.shadowColor = p.color;
            this.ctx.beginPath();
            this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            this.ctx.fillStyle = p.color;
            this.ctx.fill();
            
            // Sparkle effect for attack particles
            if (p.isAttack && Math.random() < 0.1) {
                this.ctx.globalAlpha = p.alpha * 0.8;
                const sparkSize = p.size * 1.5;
                this.ctx.fillStyle = '#ffffff';
                this.ctx.fillRect(p.x - 1, p.y - sparkSize, 2, sparkSize * 2);
                this.ctx.fillRect(p.x - sparkSize, p.y - 1, sparkSize * 2, 2);
            }
            
            this.ctx.restore();
        });
    }
    
    drawFirewall() {
        const time = Date.now() / 1000;
        
        // Apply perspective dimming
        const isDimmed = this.perspectiveEffects[this.currentPerspective].dim.includes('firewall');
        const isHighlighted = this.perspectiveEffects[this.currentPerspective].highlight === 'firewall';
        
        this.ctx.save();
        if (isDimmed) {
            this.ctx.globalAlpha = 0.3;
        } else if (isHighlighted) {
            this.ctx.globalAlpha = 1.0;
            // Add highlight glow
            this.ctx.shadowBlur = 40;
            this.ctx.shadowColor = 'rgba(0, 212, 255, 0.9)';
        }
        
        // Server rack body
        const serverWidth = 60;
        const serverHeight = 80;
        const x = this.firewallX - serverWidth / 2;
        const y = this.firewallY - serverHeight / 2;
        
        // Main server body with gradient
        const gradient = this.ctx.createLinearGradient(x, y, x, y + serverHeight);
        gradient.addColorStop(0, 'rgba(0, 150, 200, 0.8)');
        gradient.addColorStop(1, 'rgba(0, 100, 150, 0.8)');
        this.ctx.fillStyle = gradient;
        this.ctx.fillRect(x, y, serverWidth, serverHeight);
        
        // Border
        this.ctx.strokeStyle = '#00d4ff';
        this.ctx.lineWidth = 3;
        this.ctx.shadowBlur = 20;
        this.ctx.shadowColor = '#00d4ff';
        this.ctx.strokeRect(x, y, serverWidth, serverHeight);
        
        // Server rack segments (horizontal lines)
        this.ctx.strokeStyle = '#00d4ff';
        this.ctx.lineWidth = 2;
        for (let i = 1; i < 4; i++) {
            this.ctx.beginPath();
            this.ctx.moveTo(x, y + (serverHeight / 4) * i);
            this.ctx.lineTo(x + serverWidth, y + (serverHeight / 4) * i);
            this.ctx.stroke();
        }
        
        // Blinking LED lights
        const leds = [
            { x: x + 10, color: Math.random() > 0.5 ? '#00ff00' : '#003300' },
            { x: x + 20, color: Math.random() > 0.5 ? '#00d4ff' : '#003344' },
            { x: x + 30, color: Math.random() > 0.5 ? '#ff6b6b' : '#330000' },
            { x: x + 40, color: Math.random() > 0.5 ? '#00ff00' : '#003300' },
            { x: x + 50, color: Math.random() > 0.5 ? '#ffb347' : '#332200' }
        ];
        
        leds.forEach(led => {
            this.ctx.fillStyle = led.color;
            this.ctx.beginPath();
            this.ctx.arc(led.x, y + 10, 3, 0, Math.PI * 2);
            this.ctx.fill();
        });
        
        // Firewall text label
        this.ctx.font = 'bold 11px Inter';
        this.ctx.fillStyle = '#00d4ff';
        this.ctx.textAlign = 'center';
        this.ctx.textBaseline = 'middle';
        this.ctx.shadowBlur = 10;
        this.ctx.shadowColor = '#00d4ff';
        this.ctx.fillText('FIREWALL', this.firewallX, this.firewallY);
        
        // Pulsing protection field
        const pulseSize = 90 + Math.sin(time * 2) * 12;
        this.ctx.beginPath();
        this.ctx.arc(this.firewallX, this.firewallY, pulseSize, 0, Math.PI * 2);
        this.ctx.strokeStyle = `rgba(0, 212, 255, ${0.3 + Math.sin(time * 2) * 0.15})`;
        this.ctx.lineWidth = 2;
        this.ctx.shadowBlur = 20;
        this.ctx.shadowColor = '#00d4ff';
        this.ctx.stroke();
        
        // Vertical energy beams (up and down)
        this.ctx.strokeStyle = `rgba(0, 212, 255, ${0.2 + Math.sin(time * 3) * 0.1})`;
        this.ctx.lineWidth = 3;
        this.ctx.beginPath();
        this.ctx.moveTo(this.firewallX, 0);
        this.ctx.lineTo(this.firewallX, this.canvas.height);
        this.ctx.stroke();
        
        this.ctx.restore();
    }
    
    createExplosion(x, y, color) {
        for (let i = 0; i < 12; i++) {
            const angle = (Math.PI * 2 / 12) * i;
            const speed = 2 + Math.random() * 3;
            this.explosions.push({
                x, y,
                vx: Math.cos(angle) * speed,
                vy: Math.sin(angle) * speed,
                size: 3 + Math.random() * 3,
                color: color,
                alpha: 1,
                life: 1
            });
        }
    }
    
    updateExplosions() {
        for (let i = this.explosions.length - 1; i >= 0; i--) {
            const e = this.explosions[i];
            e.x += e.vx;
            e.y += e.vy;
            e.vx *= 0.95;
            e.vy *= 0.95;
            e.life -= 0.02;
            e.alpha = e.life;
            
            if (e.life <= 0) {
                this.explosions.splice(i, 1);
            }
        }
    }
    
    drawExplosions() {
        this.explosions.forEach(e => {
            this.ctx.save();
            this.ctx.globalAlpha = e.alpha;
            this.ctx.beginPath();
            this.ctx.arc(e.x, e.y, e.size, 0, Math.PI * 2);
            this.ctx.fillStyle = e.color;
            this.ctx.shadowBlur = 20;
            this.ctx.shadowColor = e.color;
            this.ctx.fill();
            this.ctx.restore();
        });
    }
    
    drawAttacker() {
        const time = Date.now() / 1000;
        
        // Apply perspective dimming
        const isDimmed = this.perspectiveEffects[this.currentPerspective].dim.includes('attacker');
        const isHighlighted = this.perspectiveEffects[this.currentPerspective].highlight === 'attacker';
        
        this.ctx.save();
        if (isDimmed) {
            this.ctx.globalAlpha = 0.3;
        } else if (isHighlighted) {
            this.ctx.globalAlpha = 1.0;
            // Add highlight glow
            this.ctx.shadowBlur = 30;
            this.ctx.shadowColor = 'rgba(255, 107, 107, 0.8)';
        }
        
        // Computer monitor/screen
        this.ctx.fillStyle = 'rgba(255, 107, 107, 0.2)';
        this.ctx.fillRect(this.attackerX - 35, this.attackerY - 25, 70, 50);
        
        this.ctx.strokeStyle = '#ff6b6b';
        this.ctx.lineWidth = 3;
        this.ctx.shadowBlur = 15;
        this.ctx.shadowColor = '#ff6b6b';
        this.ctx.strokeRect(this.attackerX - 35, this.attackerY - 25, 70, 50);
        
        // Danger X symbol
        this.ctx.strokeStyle = '#ff6b6b';
        this.ctx.lineWidth = 4;
        this.ctx.beginPath();
        this.ctx.moveTo(this.attackerX - 15, this.attackerY - 15);
        this.ctx.lineTo(this.attackerX + 15, this.attackerY + 15);
        this.ctx.moveTo(this.attackerX + 15, this.attackerY - 15);
        this.ctx.lineTo(this.attackerX - 15, this.attackerY + 15);
        this.ctx.stroke();
        
        // Computer base/stand
        this.ctx.fillStyle = '#ff6b6b';
        this.ctx.fillRect(this.attackerX - 15, this.attackerY + 25, 30, 5);
        this.ctx.fillRect(this.attackerX - 25, this.attackerY + 30, 50, 3);
        
        // Pulsing danger aura
        const pulseSize = 60 + Math.sin(time * 3) * 10;
        this.ctx.beginPath();
        this.ctx.arc(this.attackerX, this.attackerY, pulseSize, 0, Math.PI * 2);
        this.ctx.strokeStyle = `rgba(255, 107, 107, ${0.3 + Math.sin(time * 3) * 0.2})`;
        this.ctx.lineWidth = 2;
        this.ctx.stroke();
        
        // Attacker label
        this.ctx.font = 'bold 16px Inter';
        this.ctx.fillStyle = '#ff6b6b';
        this.ctx.textAlign = 'center';
        this.ctx.textBaseline = 'alphabetic';
        this.ctx.shadowBlur = 10;
        this.ctx.fillText('ATTACKER', this.attackerX, this.attackerY - 70);
        this.ctx.font = 'bold 12px Inter';
        this.ctx.fillStyle = '#ff6b6b';
        this.ctx.fillText('(Malicious)', this.attackerX, this.attackerY + 55);
        
        this.ctx.restore();
    }
    
    drawTargetServer() {
        const time = Date.now() / 1000;
        
        // Apply perspective dimming
        const isDimmed = this.perspectiveEffects[this.currentPerspective].dim.includes('defender');
        const isHighlighted = this.perspectiveEffects[this.currentPerspective].highlight === 'defender';
        
        this.ctx.save();
        if (isDimmed) {
            this.ctx.globalAlpha = 0.3;
        } else if (isHighlighted) {
            this.ctx.globalAlpha = 1.0;
            // Add highlight glow
            this.ctx.shadowBlur = 30;
            this.ctx.shadowColor = 'rgba(0, 255, 135, 0.8)';
        }
        
        // Computer monitor/screen
        this.ctx.fillStyle = 'rgba(0, 255, 166, 0.2)';
        this.ctx.fillRect(this.targetX - 35, this.targetY - 25, 70, 50);
        
        this.ctx.strokeStyle = '#00ffa6';
        this.ctx.lineWidth = 3;
        this.ctx.shadowBlur = 15;
        this.ctx.shadowColor = '#00ffa6';
        this.ctx.strokeRect(this.targetX - 35, this.targetY - 25, 70, 50);
        
        // Checkmark symbol
        this.ctx.strokeStyle = '#00ffa6';
        this.ctx.lineWidth = 5;
        this.ctx.beginPath();
        this.ctx.moveTo(this.targetX - 15, this.targetY);
        this.ctx.lineTo(this.targetX - 5, this.targetY + 12);
        this.ctx.lineTo(this.targetX + 15, this.targetY - 12);
        this.ctx.stroke();
        
        // Computer base/stand
        this.ctx.fillStyle = '#00ffa6';
        this.ctx.fillRect(this.targetX - 15, this.targetY + 25, 30, 5);
        this.ctx.fillRect(this.targetX - 25, this.targetY + 30, 50, 3);
        
        // Protected shield aura
        const pulseSize = 60 + Math.sin(time * 2) * 8;
        this.ctx.beginPath();
        this.ctx.arc(this.targetX, this.targetY, pulseSize, 0, Math.PI * 2);
        this.ctx.strokeStyle = `rgba(0, 255, 166, ${0.4 + Math.sin(time * 2) * 0.2})`;
        this.ctx.lineWidth = 2;
        this.ctx.stroke();
        
        // Target label
        this.ctx.font = 'bold 16px Inter';
        this.ctx.fillStyle = '#00ffa6';
        this.ctx.textAlign = 'center';
        this.ctx.textBaseline = 'alphabetic';
        this.ctx.shadowBlur = 10;
        this.ctx.fillText('VICTIM / TARGET', this.targetX, this.targetY - 70);
        this.ctx.font = 'bold 12px Inter';
        this.ctx.fillStyle = '#00ffa6';
        this.ctx.fillText('(Protected)', this.targetX, this.targetY + 55);
        
        this.ctx.restore();
    }
    
    draw() {
        // Clear canvas
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        
        // Draw grid background
        this.drawGrid();
        
        // Draw connection line
        this.ctx.save();
        this.ctx.strokeStyle = 'rgba(0, 212, 255, 0.15)';
        this.ctx.lineWidth = 2;
        this.ctx.setLineDash([10, 10]);
        this.ctx.beginPath();
        this.ctx.moveTo(this.attackerX, this.attackerY);
        this.ctx.lineTo(this.firewallX, this.firewallY);
        this.ctx.lineTo(this.targetX, this.targetY);
        this.ctx.stroke();
        this.ctx.restore();
        
        // Draw attacker
        this.drawAttacker();
        
        // Draw target server
        this.drawTargetServer();
        
        // Draw particles
        this.drawParticles();
        
        // Draw explosions
        this.drawExplosions();
        
        // Draw firewall (on top)
        this.drawFirewall();
    }
    
    drawGrid() {
        this.ctx.save();
        
        const time = Date.now() / 1000;
        const gridSize = 50;
        
        // Animated grid lines
        for (let x = 0; x < this.canvas.width; x += gridSize) {
            const distanceFromCenter = Math.abs(x - this.firewallX);
            const wave = Math.sin(time * 2 + distanceFromCenter / 50) * 0.05;
            this.ctx.strokeStyle = `rgba(0, 212, 255, ${0.08 + wave})`;
            this.ctx.lineWidth = 1;
            this.ctx.beginPath();
            this.ctx.moveTo(x, 0);
            this.ctx.lineTo(x, this.canvas.height);
            this.ctx.stroke();
        }
        
        for (let y = 0; y < this.canvas.height; y += gridSize) {
            const distanceFromCenter = Math.abs(y - this.firewallY);
            const wave = Math.sin(time * 2 + distanceFromCenter / 50) * 0.05;
            this.ctx.strokeStyle = `rgba(0, 212, 255, ${0.08 + wave})`;
            this.ctx.lineWidth = 1;
            this.ctx.beginPath();
            this.ctx.moveTo(0, y);
            this.ctx.lineTo(this.canvas.width, y);
            this.ctx.stroke();
        }
        
        // Scan lines effect
        const scanY = (time * 100) % this.canvas.height;
        this.ctx.strokeStyle = 'rgba(0, 255, 166, 0.15)';
        this.ctx.lineWidth = 2;
        this.ctx.beginPath();
        this.ctx.moveTo(0, scanY);
        this.ctx.lineTo(this.canvas.width, scanY);
        this.ctx.stroke();
        
        // Corner brackets (HUD style)
        const bracketSize = 30;
        this.ctx.strokeStyle = 'rgba(0, 212, 255, 0.4)';
        this.ctx.lineWidth = 2;
        
        // Top-left
        this.ctx.beginPath();
        this.ctx.moveTo(20, 20 + bracketSize);
        this.ctx.lineTo(20, 20);
        this.ctx.lineTo(20 + bracketSize, 20);
        this.ctx.stroke();
        
        // Top-right
        this.ctx.beginPath();
        this.ctx.moveTo(this.canvas.width - 20 - bracketSize, 20);
        this.ctx.lineTo(this.canvas.width - 20, 20);
        this.ctx.lineTo(this.canvas.width - 20, 20 + bracketSize);
        this.ctx.stroke();
        
        // Bottom-left
        this.ctx.beginPath();
        this.ctx.moveTo(20, this.canvas.height - 20 - bracketSize);
        this.ctx.lineTo(20, this.canvas.height - 20);
        this.ctx.lineTo(20 + bracketSize, this.canvas.height - 20);
        this.ctx.stroke();
        
        // Bottom-right
        this.ctx.beginPath();
        this.ctx.moveTo(this.canvas.width - 20 - bracketSize, this.canvas.height - 20);
        this.ctx.lineTo(this.canvas.width - 20, this.canvas.height - 20);
        this.ctx.lineTo(this.canvas.width - 20, this.canvas.height - 20 - bracketSize);
        this.ctx.stroke();
        
        this.ctx.restore();
    }
    
    updateStats() {
        // Update stat values
        document.getElementById('totalRequests').textContent = this.stats.totalRequests;
        document.getElementById('attacksDetected').textContent = this.stats.attacksDetected;
        document.getElementById('requestsBlocked').textContent = this.stats.requestsBlocked;
        document.getElementById('rateLimited').textContent = this.stats.rateLimited;
        document.getElementById('reqPerSec').textContent = this.stats.reqPerSec;
        
        // Calculate success rate based on perspective
        let successRate;
        if (this.currentPerspective === 'attacker') {
            // Attacker sees "success" as attacks that got through
            const attacksThrough = this.stats.attacksDetected - this.stats.requestsBlocked;
            successRate = this.stats.attacksDetected > 0 
                ? ((attacksThrough / this.stats.attacksDetected) * 100).toFixed(1)
                : 0;
        } else if (this.currentPerspective === 'firewall' || this.currentPerspective === 'defender') {
            // Firewall/Defender sees "success" as attacks blocked
            successRate = this.stats.attacksDetected > 0 
                ? ((this.stats.requestsBlocked / this.stats.attacksDetected) * 100).toFixed(1)
                : 100;
        } else {
            // All view shows defense success rate
            successRate = this.stats.attacksDetected > 0 
                ? ((this.stats.requestsBlocked / this.stats.attacksDetected) * 100).toFixed(1)
                : 100;
        }
        
        document.getElementById('successRate').textContent = successRate + '%';
        
        // Update stat labels based on perspective
        this.updateStatLabels();
    }
    
    updateStatLabels() {
        const labels = {
            all: {
                reqPerSec: 'Requests/sec:',
                totalRequests: 'Total Requests:',
                attacksDetected: 'Attacks Detected:',
                requestsBlocked: 'Requests Blocked:',
                rateLimited: 'Rate Limited:',
                successRate: 'Success Rate:'
            },
            attacker: {
                reqPerSec: 'Attack Rate:',
                totalRequests: 'Packets Sent:',
                attacksDetected: 'Attacks Launched:',
                requestsBlocked: 'Attacks Failed:',
                rateLimited: 'Throttled:',
                successRate: 'Penetration Rate:'
            },
            firewall: {
                reqPerSec: 'Traffic Rate:',
                totalRequests: 'Inspected:',
                attacksDetected: 'Threats Found:',
                requestsBlocked: 'Threats Blocked:',
                rateLimited: 'Rate Limited:',
                successRate: 'Block Rate:'
            },
            defender: {
                reqPerSec: 'Incoming Rate:',
                totalRequests: 'Total Traffic:',
                attacksDetected: 'Attacks Detected:',
                requestsBlocked: 'Attacks Stopped:',
                rateLimited: 'Rate Limited:',
                successRate: 'Protection Rate:'
            }
        };
        
        const currentLabels = labels[this.currentPerspective] || labels.all;
        
        // Update all stat labels
        const statItems = document.querySelectorAll('.stat-item .stat-label');
        if (statItems[0]) statItems[0].textContent = currentLabels.reqPerSec;
        if (statItems[1]) statItems[1].textContent = currentLabels.totalRequests;
        if (statItems[2]) statItems[2].textContent = currentLabels.attacksDetected;
        if (statItems[3]) statItems[3].textContent = currentLabels.requestsBlocked;
        if (statItems[4]) statItems[4].textContent = currentLabels.rateLimited;
        if (statItems[5]) statItems[5].textContent = currentLabels.successRate;
    }
    
    updateChart() {
        const now = new Date().toLocaleTimeString();
        const normalTraffic = this.currentAttack === 'normal' ? this.stats.reqPerSec : Math.max(0, this.stats.reqPerSec - this.attacks[this.currentAttack].intensity);
        const attackTraffic = this.currentAttack !== 'normal' ? this.stats.reqPerSec : 0;
        const blocked = this.stats.reqPerSec > 0 ? Math.floor(attackTraffic * this.attacks[this.currentAttack].blockRate) : 0;
        
        this.trafficData.labels.push(now);
        this.trafficData.datasets[0].data.push(normalTraffic);
        this.trafficData.datasets[1].data.push(attackTraffic);
        this.trafficData.datasets[2].data.push(blocked);
        
        // Keep only last 15 data points
        if (this.trafficData.labels.length > 15) {
            this.trafficData.labels.shift();
            this.trafficData.datasets.forEach(dataset => dataset.data.shift());
        }
        
        this.chart.update('none');
    }
    
    addLog(message, type = 'info', perspective = 'all') {
        // Filter logs based on current perspective
        if (this.currentPerspective !== 'all' && perspective !== 'all' && perspective !== this.currentPerspective) {
            return; // Don't show logs from other perspectives
        }
        
        const logContainer = document.getElementById('logContainer');
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${type} perspective-${perspective}`;
        
        // Add perspective badge
        const badges = {
            attacker: '<span class="perspective-badge attacker">🎯 ATTACKER</span>',
            firewall: '<span class="perspective-badge firewall">🛡️ FIREWALL</span>',
            defender: '<span class="perspective-badge defender">✅ DEFENDER</span>',
            all: ''
        };
        
        const badge = this.currentPerspective === 'all' && perspective !== 'all' ? badges[perspective] : '';
        logEntry.innerHTML = `<span class="log-timestamp">[${timestamp}]</span> ${badge} ${message}`;
        
        logContainer.insertBefore(logEntry, logContainer.firstChild);
        
        // Keep only last 100 logs
        while (logContainer.children.length > 100) {
            logContainer.removeChild(logContainer.lastChild);
        }
    }
    
    startAnimation() {
        let lastTime = Date.now();
        let reqCounter = 0;
        let lastSecond = Math.floor(Date.now() / 1000);
        
        const animate = () => {
            const now = Date.now();
            const deltaTime = now - lastTime;
            lastTime = now;
            
            if (this.isRunning) {
                const attack = this.attacks[this.currentAttack];
                const spawnRate = attack.intensity;
                
                // Create particles based on attack intensity
                for (let i = 0; i < spawnRate; i++) {
                    if (Math.random() < 0.3) {
                        this.createParticle();
                        reqCounter++;
                    }
                }
                
                // Update particles
                this.updateParticles();
                
                // Update explosions
                this.updateExplosions();
                
                // Calculate requests per second
                const currentSecond = Math.floor(now / 1000);
                if (currentSecond !== lastSecond) {
                    this.stats.reqPerSec = reqCounter;
                    reqCounter = 0;
                    lastSecond = currentSecond;
                    
                    // Update chart every second
                    this.updateChart();
                }
            }
            
            // Draw everything
            this.draw();
            
            // Update stats display
            this.updateStats();
            
            requestAnimationFrame(animate);
        };
        
        animate();
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const demo = new VisualizationDemo();
    window.visualizationDemo = demo; // Make globally accessible for debugging
});
