"""
Fixed vulnerable_home function with proper CSS escaping
"""

# This is the corrected vulnerable_home function
vulnerable_home_fixed = '''
@vulnerable_app.get("/", response_class=HTMLResponse)
async def vulnerable_home(request: Request):
    """Enhanced homepage with role-based navigation"""
    # Get search query from URL parameters (vulnerable to XSS)
    search = request.query_params.get("search", "")
    
    return HTMLResponse(content=f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnShop - Online Store</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; min-height: 100vh; }}
            .header {{ background: linear-gradient(135deg, #007bff, #0056b3); color: white; padding: 40px; text-align: center; }}
            .hero {{ background: #f8f9fa; padding: 50px; text-align: center; }}
            .auth-section {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 30px; padding: 40px; background: #e9ecef; }}
            .auth-card {{ background: white; padding: 30px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); text-align: center; }}
            .auth-card h3 {{ margin-top: 0; }}
            .btn {{ display: inline-block; padding: 12px 25px; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 10px; transition: all 0.3s; }}
            .btn-primary {{ background: #007bff; color: white; }}
            .btn-success {{ background: #28a745; color: white; }}
            .btn-danger {{ background: #dc3545; color: white; }}
            .btn:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }}
            .nav {{ display: flex; justify-content: center; gap: 30px; padding: 20px; background: #343a40; }}
            .nav a {{ color: white; text-decoration: none; font-weight: bold; padding: 10px 20px; border-radius: 5px; }}
            .footer {{ background: #495057; color: white; padding: 20px; text-align: center; }}
            .search-box {{ text-align: center; margin: 30px 0; padding: 12px; }}
            .search-box input {{ padding: 12px 25px; width: 400px; border: 1px solid #ddd; border-radius: 25px; }}
            .features {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; padding: 40px; background: #f8f9fa; }}
            .feature-card {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .feature-card h4 {{ color: #007bff; margin-bottom: 10px; }}
            .warning {{ background: #fff3cd; color: #856404; padding: 20px; border-radius: 10px; margin: 30px; border: 1px solid #ffeaa7; text-align: center; }}
            .stats {{ background: #343a40; color: white; padding: 20px; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛒 VulnShop</h1>
                <p>Your One-Stop Vulnerable Shopping Experience</p>
                <p style="font-size: 18px; margin-top: 20px;">🎯 Educational Platform for Security Testing</p>
            </div>
            
            <div class="warning">
                ⚠️ <strong>IMPORTANT:</strong> This is a deliberately vulnerable application created for WAF testing and security education purposes only. Do not use in production environments!
            </div>
            
            <div class="stats">
                <h3>📊 VulnShop Statistics</h3>
                <p>🛍️ 20 Products Available | 🏪 7 Categories | 🔍 SQL Injection Vulnerable | 🎯 Perfect for WAF Testing</p>
            </div>
            
            <div class="auth-section">
                <div class="auth-card">
                    <h3>👤 Customer Portal</h3>
                    <p>Shop products, manage orders, and explore our vulnerable customer system.</p>
                    <a href="/login" class="btn btn-success">Customer Login</a>
                    <a href="/register" class="btn btn-primary">Create Account</a>
                    <div style="background: #d1ecf1; padding: 15px; border-radius: 8px; margin: 15px 0; font-size: 14px;">
                        <strong>Demo Account:</strong><br>
                        Username: user<br>
                        Password: password
                    </div>
                </div>
                
                <div class="auth-card">
                    <h3>🔐 Admin Panel</h3>
                    <p>Administrative access for managing users and system configuration.</p>
                    <a href="/admin" class="btn btn-danger">Admin Access</a>
                    <div style="background: #d1ecf1; padding: 15px; border-radius: 8px; margin: 15px 0; font-size: 14px;">
                        <strong>Admin Account:</strong><br>
                        Username: admin<br>
                        Password: admin123
                    </div>
                </div>
                
                <div class="auth-card">
                    <h3>🛍️ Browse Catalog</h3>
                    <p>Explore our comprehensive product catalog with 20 items across 7 categories.</p>
                    <a href="/products" class="btn btn-primary">View Products</a>
                    <a href="/contact" class="btn btn-primary">Contact Us</a>
                </div>
            </div>
            
            <div class="nav">
                <a href="/">🏠 Home</a>
                <a href="/products">🛍️ Products</a>
                <a href="/upload">📁 File Upload</a>
                <a href="/contact">📧 Contact</a>
                <a href="/login">🔑 Vulnerable Login</a>
            </div>
            
            <div class="search-box">
                <form method="GET">
                    <input type="text" name="search" placeholder="Search products (XSS vulnerable)..." value="{search}">
                    <button type="submit" style="padding: 12px 25px; background: #28a745; color: white; border: none; border-radius: 25px; cursor: pointer; margin-left: 10px;">🔍 Search</button>
                </form>
                <div style="margin: 15px 0; color: #666; font-style: italic;">
                    Search Result: {search}
                </div>
            </div>
            
            <div class="features">
                <div class="feature-card">
                    <h4>🎯 SQL Injection Testing</h4>
                    <p>Test various SQL injection attacks against our vulnerable product database with 20 realistic products.</p>
                    <ul style="text-align: left;">
                        <li><strong>Union-based:</strong> <code>/products?search=' UNION SELECT username,password FROM users--</code></li>
                        <li><strong>Boolean-based:</strong> <code>/products?id=1' AND 1=1--</code></li>
                        <li><strong>Error-based:</strong> <code>/products?id=1' OR 1=1--</code></li>
                    </ul>
                </div>
                
                <div class="feature-card">
                    <h4>🔐 Authentication Bypass</h4>
                    <p>Vulnerable login system with multiple bypass techniques available for testing.</p>
                    <ul style="text-align: left;">
                        <li><strong>SQL Injection:</strong> <code>admin' OR '1'='1</code></li>
                        <li><strong>Comment Injection:</strong> <code>admin'--</code></li>
                        <li><strong>Union Injection:</strong> <code>' UNION SELECT 'admin','admin123'--</code></li>
                    </ul>
                </div>
                
                <div class="feature-card">
                    <h4>📁 File Upload Vulnerabilities</h4>
                    <p>Unrestricted file upload endpoint accepting any file type without validation.</p>
                    <ul style="text-align: left;">
                        <li><strong>Web Shells:</strong> Upload .php, .asp files</li>
                        <li><strong>Double Extension:</strong> image.jpg.php</li>
                        <li><strong>Executable Files:</strong> .exe, .bat files</li>
                    </ul>
                </div>
                
                <div class="feature-card">
                    <h4>🌐 Cross-Site Scripting (XSS)</h4>
                    <p>Multiple XSS vulnerabilities in search and contact forms.</p>
                    <ul style="text-align: left;">
                        <li><strong>Reflected XSS:</strong> Search functionality</li>
                        <li><strong>Stored XSS:</strong> Contact form messages</li>
                        <li><strong>DOM XSS:</strong> URL parameter reflection</li>
                    </ul>
                </div>
            </div>
            
            <div class="footer">
                <p>🎓 VulnShop - Educational Security Testing Platform</p>
                <p>Created for VigilEdge WAF demonstration and security research</p>
                <p><strong>⚠️ WARNING:</strong> Contains intentional vulnerabilities - DO NOT use in production!</p>
            </div>
        </div>
    </body>
    </html>
    """)
'''
