/**
 * VigilEdge Global Theme Manager
 * Applies theme settings across all pages
 */

class ThemeManager {
    constructor() {
        this.currentTheme = 'dark';
        this.themes = {
            dark: {
                '--primary-bg': 'linear-gradient(135deg, #0f0f23 0%, #1a1a2e 30%, #16213e 60%, #0f3460 100%)',
                '--glass-bg': 'rgba(255, 255, 255, 0.06)',
                '--glass-border': 'rgba(100, 200, 255, 0.2)',
                '--card-bg': 'rgba(30, 30, 50, 0.85)',
                '--sidebar-bg': 'rgba(20, 25, 45, 0.95)',
                '--cyber-blue': '#00d4ff',
                '--cyber-teal': '#00ffa6',
                '--cyber-purple': '#7c3aed',
                '--text-primary': '#ffffff',
                '--text-secondary': '#e1e7f5',
                '--text-muted': '#94a3b8',
                '--success': '#00ff87',
                '--warning': '#ffb347',
                '--danger': '#ff6b6b'
            },
            light: {
                '--primary-bg': 'linear-gradient(135deg, #f0f4f8 0%, #d9e2ec 50%, #bcccdc 100%)',
                '--glass-bg': 'rgba(255, 255, 255, 0.8)',
                '--glass-border': 'rgba(0, 0, 0, 0.1)',
                '--card-bg': 'rgba(255, 255, 255, 0.95)',
                '--sidebar-bg': 'rgba(248, 250, 252, 0.98)',
                '--cyber-blue': '#0066cc',
                '--cyber-teal': '#00b894',
                '--cyber-purple': '#6c5ce7',
                '--text-primary': '#1a202c',
                '--text-secondary': '#2d3748',
                '--text-muted': '#4a5568',
                '--success': '#00d68f',
                '--warning': '#ffa502',
                '--danger': '#ff3838'
            },
            blue: {
                '--primary-bg': 'linear-gradient(135deg, #0a1929 0%, #1a2980 50%, #26d0ce 100%)',
                '--glass-bg': 'rgba(255, 255, 255, 0.08)',
                '--glass-border': 'rgba(38, 208, 206, 0.3)',
                '--card-bg': 'rgba(20, 30, 60, 0.85)',
                '--sidebar-bg': 'rgba(15, 25, 50, 0.95)',
                '--cyber-blue': '#00d4ff',
                '--cyber-teal': '#26d0ce',
                '--cyber-purple': '#667eea',
                '--text-primary': '#ffffff',
                '--text-secondary': '#e1e7f5',
                '--text-muted': '#94a3b8',
                '--success': '#00ff87',
                '--warning': '#ffd166',
                '--danger': '#ff6b6b'
            }
        };
    }

    /**
     * Initialize theme from localStorage or fetch from API
     */
    async init() {
        try {
            // Try to get theme from API settings
            const response = await fetch('/api/v1/settings');
            if (response.ok) {
                const settings = await response.json();
                if (settings.theme && settings.theme.selected_theme) {
                    this.applyTheme(settings.theme.selected_theme);
                    return;
                }
            }
        } catch (error) {
            console.warn('Could not fetch theme from API, using default:', error);
        }

        // Fallback to localStorage or default
        const savedTheme = localStorage.getItem('vigiledge_theme') || 'dark';
        this.applyTheme(savedTheme);
    }

    /**
     * Apply theme to the page
     */
    applyTheme(themeName) {
        if (!this.themes[themeName]) {
            console.warn(`Theme "${themeName}" not found, using dark theme`);
            themeName = 'dark';
        }

        this.currentTheme = themeName;
        const theme = this.themes[themeName];
        const root = document.documentElement;

        // Apply all CSS variables
        Object.entries(theme).forEach(([property, value]) => {
            root.style.setProperty(property, value);
        });

        // Update body color for light theme
        if (themeName === 'light') {
            document.body.style.color = '#1a202c';
        } else {
            document.body.style.color = '#ffffff';
        }

        // Save to localStorage
        localStorage.setItem('vigiledge_theme', themeName);

        console.log(`✅ Theme applied: ${themeName}`);
    }

    /**
     * Get current theme name
     */
    getCurrentTheme() {
        return this.currentTheme;
    }

    /**
     * Switch to a different theme
     */
    switchTheme(themeName) {
        this.applyTheme(themeName);
    }
}

// Create global instance
const themeManager = new ThemeManager();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => themeManager.init());
} else {
    themeManager.init();
}

// Export for use in other scripts
window.themeManager = themeManager;
