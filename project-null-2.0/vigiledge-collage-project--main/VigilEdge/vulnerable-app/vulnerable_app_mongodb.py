"""
VulnShop - Vulnerable Web Application with MongoDB Backend
This application contains intentional vulnerabilities for testing purposes only.
DO NOT USE IN PRODUCTION - FOR EDUCATIONAL/TESTING PURPOSES ONLY
"""

from fastapi import FastAPI, Request, Form, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import pymongo
from pymongo import MongoClient
import os
from typing import Optional
import json
from bson import ObjectId
import datetime

# Create vulnerable app
vulnerable_app = FastAPI(
    title="VulnShop - Vulnerable E-commerce Site with MongoDB",
    description="Intentionally vulnerable application for WAF testing with MongoDB backend",
    version="1.0.0"
)

# MongoDB connection
MONGO_URL = "mongodb://localhost:27017/"
DATABASE_NAME = "vulnshop"

def get_db_connection():
    """Get MongoDB connection"""
    try:
        client = MongoClient(MONGO_URL)
        return client[DATABASE_NAME]
    except Exception as e:
        print(f"MongoDB connection error: {e}")
        return None

# Initialize vulnerable database
def init_vulnerable_db():
    """Initialize MongoDB with vulnerable data"""
    try:
        db = get_db_connection()
        if db is None:
            print("❌ Failed to connect to MongoDB")
            return False
            
        # Drop existing collections for fresh start
        db.users.drop()
        db.products.drop()
        
        # Create vulnerable users collection
        users_data = [
            {
                "_id": ObjectId(),
                "username": "admin",
                "password": "admin123",  # Plain text password (vulnerable!)
                "email": "admin@vulnshop.com",
                "is_admin": True,
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "username": "user",
                "password": "password",  # Plain text password (vulnerable!)
                "email": "user@vulnshop.com",
                "is_admin": False,
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "username": "guest",
                "password": "guest",  # Plain text password (vulnerable!)
                "email": "guest@vulnshop.com",
                "is_admin": False,
                "created_at": datetime.datetime.utcnow()
            }
        ]
        
        # Insert users
        db.users.insert_many(users_data)
        
        # Create comprehensive products collection for VulnShop
        products_data = [
            {
                "_id": ObjectId(),
                "name": "Gaming Laptop Pro X1",
                "price": 1899.99,
                "description": "Ultimate gaming laptop with RTX 4080, 32GB RAM, 1TB SSD. Perfect for gaming and content creation.",
                "category": "Electronics",
                "subcategory": "Laptops",
                "brand": "TechMaster",
                "stock": 15,
                "rating": 4.8,
                "image_url": "/static/images/gaming-laptop.jpg",
                "features": ["RTX 4080 GPU", "32GB DDR5 RAM", "1TB NVMe SSD", "17.3\" 4K Display"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Smartphone Pro Max 256GB",
                "price": 1199.99,
                "description": "Latest flagship smartphone with triple camera system, 5G connectivity, and all-day battery life.",
                "category": "Electronics",
                "subcategory": "Smartphones",
                "brand": "PhoneTech",
                "stock": 42,
                "rating": 4.6,
                "image_url": "/static/images/smartphone-pro.jpg",
                "features": ["Triple Camera", "5G Ready", "256GB Storage", "Fast Charging"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Wireless Noise-Canceling Headphones",
                "price": 299.99,
                "description": "Premium wireless headphones with active noise cancellation and 30-hour battery life.",
                "category": "Audio",
                "subcategory": "Headphones",
                "brand": "AudioElite",
                "stock": 67,
                "rating": 4.7,
                "image_url": "/static/images/headphones.jpg",
                "features": ["Active Noise Cancellation", "30hr Battery", "Bluetooth 5.0", "Quick Charge"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "4K Smart TV 65 inch",
                "price": 799.99,
                "description": "Ultra HD 4K Smart TV with HDR support, built-in streaming apps, and voice control.",
                "category": "Electronics",
                "subcategory": "Televisions",
                "brand": "ViewMaster",
                "stock": 23,
                "rating": 4.5,
                "image_url": "/static/images/smart-tv.jpg",
                "features": ["4K Ultra HD", "HDR Support", "Smart TV Platform", "Voice Control"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Professional DSLR Camera Kit",
                "price": 1299.99,
                "description": "Professional DSLR camera with 24MP sensor, 4K video recording, and complete lens kit.",
                "category": "Electronics",
                "subcategory": "Cameras",
                "brand": "PhotoPro",
                "stock": 18,
                "rating": 4.9,
                "image_url": "/static/images/dslr-camera.jpg",
                "features": ["24MP Sensor", "4K Video", "Lens Kit Included", "Weather Sealed"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Smart Fitness Watch",
                "price": 249.99,
                "description": "Advanced fitness tracking smartwatch with GPS, heart rate monitor, and 7-day battery.",
                "category": "Wearables",
                "subcategory": "Smartwatches",
                "brand": "FitTracker",
                "stock": 89,
                "rating": 4.4,
                "image_url": "/static/images/smartwatch.jpg",
                "features": ["GPS Tracking", "Heart Rate Monitor", "7-day Battery", "Water Resistant"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Mechanical Gaming Keyboard RGB",
                "price": 159.99,
                "description": "Mechanical gaming keyboard with RGB backlighting, Cherry MX switches, and programmable keys.",
                "category": "Accessories",
                "subcategory": "Keyboards",
                "brand": "GameGear",
                "stock": 156,
                "rating": 4.6,
                "image_url": "/static/images/gaming-keyboard.jpg",
                "features": ["Cherry MX Switches", "RGB Backlighting", "Programmable Keys", "Aluminum Frame"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Wireless Gaming Mouse",
                "price": 89.99,
                "description": "High-precision wireless gaming mouse with 16000 DPI sensor and customizable buttons.",
                "category": "Accessories",
                "subcategory": "Mice",
                "brand": "GameGear",
                "stock": 234,
                "rating": 4.5,
                "image_url": "/static/images/gaming-mouse.jpg",
                "features": ["16000 DPI Sensor", "Wireless", "Customizable Buttons", "RGB Lighting"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Bluetooth Portable Speaker",
                "price": 79.99,
                "description": "Waterproof portable Bluetooth speaker with 360-degree sound and 12-hour battery.",
                "category": "Audio",
                "subcategory": "Speakers",
                "brand": "SoundWave",
                "stock": 78,
                "rating": 4.3,
                "image_url": "/static/images/bluetooth-speaker.jpg",
                "features": ["360° Sound", "Waterproof", "12hr Battery", "Voice Assistant"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "USB-C Hub Multi-Port Adapter",
                "price": 49.99,
                "description": "7-in-1 USB-C hub with HDMI, USB 3.0, SD card reader, and fast charging support.",
                "category": "Accessories",
                "subcategory": "Adapters",
                "brand": "ConnectPro",
                "stock": 189,
                "rating": 4.2,
                "image_url": "/static/images/usb-hub.jpg",
                "features": ["7-in-1 Design", "HDMI 4K Output", "Fast Charging", "Compact Design"],
                "created_at": datetime.datetime.utcnow()
            }
        ]
        
        # Insert products
        db.products.insert_many(products_data)
        
        print("✅ MongoDB VulnShop database initialized successfully!")
        print(f"📊 Created {len(users_data)} users and {len(products_data)} products")
        return True
        
    except Exception as e:
        print(f"❌ Error initializing MongoDB: {e}")
        return False

@vulnerable_app.get("/", response_class=HTMLResponse)
async def vulnerable_home(request: Request):
    """Enhanced homepage with MongoDB backend"""
    # Get search query from URL parameters (vulnerable to XSS)
    search = request.query_params.get("search", "")
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnShop - MongoDB Edition</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                min-height: 100vh;
            }}
            .header {{
                background: linear-gradient(135deg, #28a745, #20c997);
                color: white;
                padding: 40px;
                text-align: center;
            }}
            .warning {{
                background: #fff3cd;
                color: #856404;
                padding: 20px;
                border-radius: 10px;
                margin: 30px;
                border: 1px solid #ffeaa7;
            }}
            .auth-section {{
                display: grid;
                grid-template-columns: 1fr 1fr 1fr;
                gap: 30px;
                padding: 40px;
                background: #e9ecef;
            }}
            .auth-card {{
                background: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                text-align: center;
            }}
            .btn {{
                display: inline-block;
                padding: 12px 25px;
                text-decoration: none;
                border-radius: 8px;
                font-weight: bold;
                margin: 10px;
                transition: all 0.3s;
            }}
            .btn-primary {{
                background: #007bff;
                color: white;
            }}
            .btn-success {{
                background: #28a745;
                color: white;
            }}
            .btn-danger {{
                background: #dc3545;
                color: white;
            }}
            .demo-accounts {{
                background: #d1ecf1;
                padding: 15px;
                border-radius: 8px;
                margin: 15px 0;
                font-size: 14px;
            }}
            .nav {{
                display: flex;
                justify-content: center;
                gap: 30px;
                padding: 20px;
                background: #343a40;
            }}
            .nav a {{
                color: white;
                text-decoration: none;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
            }}
            .search-box {{
                text-align: center;
                margin: 30px 0;
                padding: 20px;
            }}
            .search-box input {{
                padding: 12px;
                width: 400px;
                border: 1px solid #ddd;
                border-radius: 25px;
            }}
            .search-box button {{
                padding: 12px 25px;
                background: #28a745;
                color: white;
                border: none;
                border-radius: 25px;
                cursor: pointer;
                margin-left: 10px;
            }}
            .mongodb-badge {{
                background: #4CAF50;
                color: white;
                padding: 8px 16px;
                border-radius: 20px;
                font-size: 14px;
                font-weight: bold;
                display: inline-block;
                margin: 10px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛒 VulnShop</h1>
                <div class="mongodb-badge">🍃 MongoDB Edition</div>
                <p>Your One-Stop Vulnerable Shopping Experience</p>
                <p style="font-size: 18px; margin-top: 20px;">🎯 Educational Platform for Security Testing</p>
            </div>
            
            <div class="warning">
                ⚠️ <strong>IMPORTANT:</strong> This is a deliberately vulnerable application with MongoDB backend created for WAF testing and security education purposes only. Do not use in production environments!
            </div>
            
            <div class="auth-section">
                <div class="auth-card">
                    <h3>👤 Customer Portal</h3>
                    <p>Shop products, manage orders with our MongoDB-powered customer system.</p>
                    <a href="/login" class="btn btn-success">Customer Login</a>
                    <a href="/register" class="btn btn-primary">Create Account</a>
                    <div class="demo-accounts">
                        <strong>Demo Account:</strong><br>
                        Username: user<br>
                        Password: password
                    </div>
                </div>
                
                <div class="auth-card">
                    <h3>🔐 Admin Panel</h3>
                    <p>Administrative access for managing users and MongoDB data.</p>
                    <a href="/admin" class="btn btn-danger">Admin Access</a>
                    <div class="demo-accounts">
                        <strong>Admin Account:</strong><br>
                        Username: admin<br>
                        Password: admin123
                    </div>
                </div>
                
                <div class="auth-card">
                    <h3>🛍️ Browse Catalog</h3>
                    <p>Explore our MongoDB-stored product catalog.</p>
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
                <a href="/mongo-info">🍃 MongoDB Info</a>
            </div>
            
            <div class="search-box">
                <form method="GET">
                    <input type="text" name="search" placeholder="Search MongoDB products (NoSQL injection vulnerable)..." value="{search}">
                    <button type="submit">🔍 Search</button>
                </form>
                <div style="margin: 15px 0; color: #666; font-style: italic;">
                    Search Result: {search}
                </div>
            </div>
            
            <div style="text-align: center; padding: 40px;">
                <h3>🎯 MongoDB Attack Testing Endpoints</h3>
                <p>Try these NoSQL injection attacks:</p>
                <ul style="text-align: left; max-width: 800px; margin: 0 auto;">
                    <li><strong>NoSQL Injection:</strong> <code>/login</code> (try: {{"$ne": null}})</li>
                    <li><strong>MongoDB Operator Injection:</strong> <code>/products?search={{"$where": "this.price > 500"}}</code></li>
                    <li><strong>Authentication Bypass:</strong> <code>/login</code> (username: {{"$gt": ""}}, password: {{"$gt": ""}})</li>
                    <li><strong>Data Extraction:</strong> <code>/users?filter={{"$regex": ".*"}}</code></li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)

@vulnerable_app.get("/login", response_class=HTMLResponse)
async def login_form():
    """Vulnerable login form for MongoDB"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - VulnShop MongoDB</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .form-group { margin: 15px 0; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
            button { width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; }
            .warning { background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .attack-examples { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
            .mongodb-badge { background: #4CAF50; color: white; padding: 5px 10px; border-radius: 15px; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔐 Login to VulnShop <span class="mongodb-badge">🍃 MongoDB</span></h2>
            <div class="warning">
                ⚠️ This login form is vulnerable to NoSQL injection attacks!
            </div>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
            </form>
            
            <div class="attack-examples">
                <h4>🎯 NoSQL Injection Attack Examples:</h4>
                <ul>
                    <li><strong>Authentication Bypass:</strong> <code>{"$ne": null}</code></li>
                    <li><strong>Regex Injection:</strong> <code>{"$regex": ".*"}</code></li>
                    <li><strong>Operator Injection:</strong> <code>{"$gt": ""}</code></li>
                    <li><strong>JavaScript Injection:</strong> <code>{"$where": "1==1"}</code></li>
                </ul>
                <p><strong>Try entering these as username or password!</strong></p>
            </div>
            
            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.post("/login")
async def vulnerable_login(username: str = Form(...), password: str = Form(...)):
    """Vulnerable login endpoint with NoSQL injection"""
    try:
        db = get_db_connection()
        if db is None:
            return JSONResponse({
                "status": "error",
                "message": "Database connection failed"
            }, status_code=500)
        
        # VULNERABLE: Direct NoSQL injection possible
        # This allows injection of MongoDB operators
        try:
            # Try to parse as JSON for NoSQL injection
            username_query = json.loads(username) if username.startswith('{') else username
            password_query = json.loads(password) if password.startswith('{') else password
        except:
            username_query = username
            password_query = password
        
        # VULNERABLE: Building query with user input
        query = {
            "username": username_query,
            "password": password_query
        }
        
        print(f"🔍 Executing MongoDB query: {query}")  # For demonstration
        
        user = db.users.find_one(query)
        
        if user:
            # Convert ObjectId to string for JSON response
            user['_id'] = str(user['_id'])
            return JSONResponse({
                "status": "success",
                "message": f"Login successful! Welcome {user['username']}",
                "user": user,
                "executed_query": str(query)  # Show the vulnerable query
            })
        else:
            return JSONResponse({
                "status": "error",
                "message": "Invalid credentials",
                "executed_query": str(query)
            }, status_code=401)
            
    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": f"Database error: {str(e)}",
            "executed_query": str(query) if 'query' in locals() else "Query failed"
        }, status_code=500)

@vulnerable_app.get("/products")
async def vulnerable_products(search: Optional[str] = None, filter: Optional[str] = None, category: Optional[str] = None):
    """Enhanced vulnerable products endpoint with comprehensive product listings"""
    try:
        db = get_db_connection()
        if db is None:
            return JSONResponse({
                "status": "error",
                "message": "Database connection failed"
            }, status_code=500)
        
        query = {{}}
        
        # Add category filter
        if category:
            query["category"] = category
        
        if search:
            # VULNERABLE: NoSQL injection in search
            try:
                if search.startswith('{{'):
                    search_query = json.loads(search)
                    query.update(search_query)
                else:
                    query["$or"] = [
                        {{"name": {{"$regex": search, "$options": "i"}}}},
                        {{"description": {{"$regex": search, "$options": "i"}}}},
                        {{"brand": {{"$regex": search, "$options": "i"}}}}
                    ]
            except:
                query["name"] = {{"$regex": search, "$options": "i"}}
        
        if filter:
            # VULNERABLE: Direct filter injection
            try:
                filter_query = json.loads(filter)
                query.update(filter_query)
            except:
                pass
        
        print(f"🔍 Executing MongoDB products query: {query}")
        
        products = list(db.products.find(query).sort("name", 1))
        
        # Convert ObjectIds to strings
        for product in products:
            product['_id'] = str(product['_id'])
        
        # Return HTML page if no specific format requested
        if not search and not filter:
            return HTMLResponse(generate_products_page(products))
        
        return JSONResponse({{
            "products": products,
            "count": len(products),
            "executed_query": str(query),
            "vulnerability": "NoSQL injection possible via 'search' and 'filter' parameters"
        }})
        
    except Exception as e:
        return JSONResponse({{
            "error": str(e),
            "executed_query": str(query) if 'query' in locals() else "Query failed",
            "message": "NoSQL injection may have caused this error"
        }}, status_code=500)

def generate_products_page(products):
    """Generate HTML page displaying all VulnShop products"""
    
    # Get unique categories for filter
    categories = set()
    for product in products:
        categories.add(product.get('category', 'Other'))
    
    products_html = ""
    for product in products:
        features_html = ""
        if 'features' in product:
            for feature in product['features']:
                features_html += f"<span class='feature-tag'>{feature}</span>"
        
        products_html += f"""
        <div class="product-card">
            <div class="product-image">
                <div class="image-placeholder">📷</div>
            </div>
            <div class="product-info">
                <h3 class="product-name">{product['name']}</h3>
                <p class="product-brand">{product.get('brand', 'Unknown Brand')}</p>
                <p class="product-price">${product['price']:.2f}</p>
                <p class="product-description">{product['description']}</p>
                <div class="product-features">
                    {features_html}
                </div>
                <div class="product-meta">
                    <span class="stock">Stock: {product['stock']}</span>
                    <span class="rating">⭐ {product.get('rating', 'N/A')}</span>
                    <span class="category">{product['category']}</span>
                </div>
                <button class="add-to-cart-btn" onclick="addToCart('{product['_id']}')">Add to Cart</button>
            </div>
        </div>
        """
    
    category_options = ""
    for cat in sorted(categories):
        category_options += f'<option value="{cat}">{cat}</option>'
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnShop Products - MongoDB Edition</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                background: white;
                min-height: 100vh;
            }}
            .header {{
                background: linear-gradient(135deg, #28a745, #20c997);
                color: white;
                padding: 30px;
                text-align: center;
                position: relative;
            }}
            .mongodb-badge {{
                background: #4CAF50;
                color: white;
                padding: 8px 16px;
                border-radius: 20px;
                font-size: 14px;
                font-weight: bold;
                display: inline-block;
                margin: 10px;
            }}
            .filters {{
                background: #f8f9fa;
                padding: 20px;
                border-bottom: 1px solid #dee2e6;
            }}
            .filter-row {{
                display: flex;
                gap: 15px;
                align-items: center;
                flex-wrap: wrap;
            }}
            .filter-group {{
                display: flex;
                flex-direction: column;
                gap: 5px;
            }}
            .filter-group label {{
                font-weight: bold;
                font-size: 14px;
            }}
            .filter-group select, .filter-group input {{
                padding: 8px 12px;
                border: 1px solid #ced4da;
                border-radius: 5px;
                font-size: 14px;
            }}
            .search-input {{
                flex: 1;
                min-width: 300px;
            }}
            .products-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
                gap: 25px;
                padding: 30px;
            }}
            .product-card {{
                background: white;
                border-radius: 12px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                overflow: hidden;
                transition: transform 0.3s ease, box-shadow 0.3s ease;
                border: 1px solid #e9ecef;
            }}
            .product-card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            }}
            .product-image {{
                height: 200px;
                background: linear-gradient(45deg, #f8f9fa, #e9ecef);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 48px;
                color: #6c757d;
            }}
            .product-info {{
                padding: 20px;
            }}
            .product-name {{
                font-size: 18px;
                font-weight: bold;
                color: #343a40;
                margin: 0 0 8px 0;
                line-height: 1.3;
            }}
            .product-brand {{
                font-size: 14px;
                color: #6c757d;
                margin: 0 0 10px 0;
                font-weight: 500;
            }}
            .product-price {{
                font-size: 24px;
                font-weight: bold;
                color: #28a745;
                margin: 0 0 12px 0;
            }}
            .product-description {{
                font-size: 14px;
                color: #495057;
                line-height: 1.5;
                margin: 0 0 15px 0;
            }}
            .product-features {{
                margin: 15px 0;
            }}
            .feature-tag {{
                display: inline-block;
                background: #e3f2fd;
                color: #1976d2;
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 12px;
                margin: 2px;
                border: 1px solid #bbdefb;
            }}
            .product-meta {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin: 15px 0;
                font-size: 13px;
                color: #6c757d;
            }}
            .stock {{
                background: #d4edda;
                color: #155724;
                padding: 3px 8px;
                border-radius: 10px;
            }}
            .rating {{
                font-weight: bold;
            }}
            .category {{
                background: #f8d7da;
                color: #721c24;
                padding: 3px 8px;
                border-radius: 10px;
            }}
            .add-to-cart-btn {{
                width: 100%;
                background: #007bff;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                cursor: pointer;
                transition: background-color 0.3s ease;
            }}
            .add-to-cart-btn:hover {{
                background: #0056b3;
            }}
            .stats {{
                background: #343a40;
                color: white;
                padding: 15px 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .nav-links {{
                text-align: center;
                padding: 20px;
                background: #f8f9fa;
                border-top: 1px solid #dee2e6;
            }}
            .nav-links a {{
                color: #007bff;
                text-decoration: none;
                margin: 0 15px;
                font-weight: bold;
            }}
            .vulnerability-info {{
                background: #fff3cd;
                color: #856404;
                padding: 15px;
                margin: 20px;
                border-radius: 8px;
                border: 1px solid #ffeaa7;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛒 VulnShop Product Catalog</h1>
                <div class="mongodb-badge">🍃 MongoDB Powered</div>
                <p>Browse our extensive collection of tech products</p>
            </div>
            
            <div class="vulnerability-info">
                <strong>🎯 Security Testing:</strong> This product search is vulnerable to NoSQL injection. 
                Try searching for: <code>{{"$where": "this.price > 500"}}</code> or <code>{{"$regex": ".*"}}</code>
            </div>
            
            <div class="filters">
                <div class="filter-row">
                    <div class="filter-group">
                        <label>Search Products:</label>
                        <input type="text" class="search-input" placeholder="Search by name, description, or brand (NoSQL injection vulnerable)..." onkeyup="searchProducts(this.value)">
                    </div>
                    <div class="filter-group">
                        <label>Category:</label>
                        <select onchange="filterByCategory(this.value)">
                            <option value="">All Categories</option>
                            {category_options}
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Injection Test:</label>
                        <select onchange="testInjection(this.value)">
                            <option value="">Select Attack</option>
                            <option value='{{"$where": "this.price > 500"}}'>Price > $500 ($where)</option>
                            <option value='{{"$regex": ".*"}}'>All Products ($regex)</option>
                            <option value='{{"rating": {{"$gte": 4.5}}}}'>High Rated ($gte)</option>
                        </select>
                    </div>
                </div>
            </div>
            
            <div class="stats">
                <span>📊 Total Products: {len(products)}</span>
                <span>🏪 Categories: {len(categories)}</span>
                <span>🔍 NoSQL Injection Testing Enabled</span>
            </div>
            
            <div class="products-grid">
                {products_html}
            </div>
            
            <div class="nav-links">
                <a href="/">🏠 Home</a>
                <a href="/login">🔐 Login</a>
                <a href="/admin">⚙️ Admin Panel</a>
                <a href="/mongo-info">🍃 Database Info</a>
                <a href="/health">❤️ Health Check</a>
            </div>
        </div>
        
        <script>
            function searchProducts(query) {{
                if (query.length > 2) {{
                    window.location.href = `/products?search=${{encodeURIComponent(query)}}`;
                }}
            }}
            
            function filterByCategory(category) {{
                if (category) {{
                    window.location.href = `/products?category=${{encodeURIComponent(category)}}`;
                }} else {{
                    window.location.href = '/products';
                }}
            }}
            
            function testInjection(payload) {{
                if (payload) {{
                    window.location.href = `/products?search=${{encodeURIComponent(payload)}}`;
                }}
            }}
            
            function addToCart(productId) {{
                alert(`Product ${{productId}} added to cart! (This would be a real cart in a production app)`);
            }}
        </script>
    </body>
    </html>
    """

@vulnerable_app.get("/mongo-info")
async def mongo_info():
    """Display MongoDB connection and database information"""
    try:
        db = get_db_connection()
        if db is None:
            return JSONResponse({
                "status": "error",
                "message": "Could not connect to MongoDB"
            }, status_code=500)
        
        # Get database stats
        stats = db.command("dbStats")
        collections = db.list_collection_names()
        
        # Get collection counts
        collection_info = {}
        for collection_name in collections:
            collection_info[collection_name] = db[collection_name].count_documents({})
        
        return JSONResponse({
            "status": "connected",
            "database": DATABASE_NAME,
            "mongodb_url": MONGO_URL,
            "collections": collections,
            "collection_counts": collection_info,
            "database_stats": {
                "storage_size": stats.get("storageSize", 0),
                "data_size": stats.get("dataSize", 0),
                "index_size": stats.get("indexSize", 0),
                "objects": stats.get("objects", 0)
            }
        })
        
    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": f"MongoDB error: {str(e)}"
        }, status_code=500)

@vulnerable_app.get("/admin")
async def admin_panel():
    """MongoDB admin panel"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel - VulnShop MongoDB</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .mongodb-badge { background: #4CAF50; color: white; padding: 5px 10px; border-radius: 15px; font-size: 12px; }
            .section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
            button { padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 VulnShop Admin Dashboard <span class="mongodb-badge">🍃 MongoDB</span></h1>
            
            <div class="section">
                <h3>📊 Database Information</h3>
                <button onclick="window.open('/mongo-info', '_blank')">View MongoDB Stats</button>
                <button onclick="window.open('/products', '_blank')">View All Products</button>
            </div>
            
            <div class="section">
                <h3>🎯 NoSQL Injection Test Endpoints</h3>
                <ul>
                    <li><a href="/login" target="_blank">Vulnerable Login Form</a></li>
                    <li><a href="/products?search={&quot;$where&quot;: &quot;this.price > 500&quot;}" target="_blank">MongoDB $where Injection</a></li>
                    <li><a href="/products?filter={&quot;$regex&quot;: &quot;.*&quot;}" target="_blank">Regex Injection Test</a></li>
                </ul>
            </div>
            
            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    """)

# Health check endpoint
@vulnerable_app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        db = get_db_connection()
        if db is None:
            return JSONResponse({
                "status": "unhealthy",
                "app": "VulnShop MongoDB",
                "database": "disconnected"
            }, status_code=503)
        
        # Test database connection
        db.command("ping")
        
        return {
            "status": "healthy",
            "app": "VulnShop MongoDB",
            "database": "connected",
            "purpose": "WAF Testing Target with MongoDB"
        }
    except Exception as e:
        return JSONResponse({
            "status": "unhealthy",
            "app": "VulnShop MongoDB",
            "database": f"error: {str(e)}"
        }, status_code=503)

def find_available_port(start_port=8082, max_attempts=10):
    """Find an available port starting from start_port"""
    import socket
    
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return None

if __name__ == "__main__":
    print("🎯 Starting VulnShop MongoDB Edition - Vulnerable Web Application")
    print("🍃 MongoDB Backend for NoSQL Injection Testing")
    print("⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("🔥 DO NOT USE IN PRODUCTION")
    
    # Initialize MongoDB database
    if not init_vulnerable_db():
        print("❌ Failed to initialize MongoDB. Make sure MongoDB is running on localhost:27017")
        print("💡 Start MongoDB with: mongod --port 27017")
        exit(1)
    
    # Find available port
    available_port = find_available_port(8082)
    if available_port is None:
        print("❌ ERROR: Could not find an available port between 8082-8091")
        print("💡 Solution: Close other applications using these ports")
        exit(1)
    
    print(f"📡 Server will start on http://localhost:{available_port}")
    
    if available_port != 8082:
        print(f"ℹ️  Note: Using port {available_port} instead of 8082 (port was in use)")
    
    import uvicorn
    uvicorn.run(vulnerable_app, host="127.0.0.1", port=available_port)
