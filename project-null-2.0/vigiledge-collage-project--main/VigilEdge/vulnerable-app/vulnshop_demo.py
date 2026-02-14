"""
VulnShop Simple Web Version - Works without MongoDB
Demonstrates the complete product catalog for the vulnerable website
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import uvicorn
from product_catalog import get_products, search_products, filter_by_category, get_categories, generate_product_html

# Create simple web app
app = FastAPI(title="VulnShop - Product Catalog Demo")

@app.get("/", response_class=HTMLResponse)
async def home():
    """Home page with product listings"""
    products = get_products()
    categories = get_categories()
    
    products_html = ""
    for product in products:
        products_html += generate_product_html(product)
    
    category_options = ""
    for cat in categories:
        category_options += f'<option value="{cat}">{cat}</option>'
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnShop - Product Catalog</title>
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
            }}
            .stats {{
                background: #343a40;
                color: white;
                padding: 15px 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .filters {{
                background: #f8f9fa;
                padding: 20px;
                text-align: center;
            }}
            .filter-group {{
                margin: 10px;
                display: inline-block;
            }}
            .filter-group select, .filter-group input {{
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin: 0 5px;
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
                transition: transform 0.3s ease;
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
            }}
            .product-brand {{
                font-size: 14px;
                color: #6c757d;
                margin: 0 0 10px 0;
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
            }}
            .product-meta {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin: 15px 0;
                font-size: 13px;
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
                font-weight: bold;
                cursor: pointer;
            }}
            .add-to-cart-btn:hover {{
                background: #0056b3;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛒 VulnShop - Product Catalog</h1>
                <p>Complete product listings for the vulnerable e-commerce website</p>
                <p style="font-size: 14px; opacity: 0.9;">🎯 Educational Platform for Security Testing</p>
            </div>
            
            <div class="stats">
                <span>📊 Total Products: {len(products)}</span>
                <span>🏪 Categories: {len(categories)}</span>
                <span>💡 Ready for MongoDB Integration</span>
            </div>
            
            <div class="filters">
                <div class="filter-group">
                    <label>🔍 Search Products:</label>
                    <input type="text" placeholder="Search by name, brand, or description..." style="width: 300px;">
                </div>
                <div class="filter-group">
                    <label>📂 Filter by Category:</label>
                    <select>
                        <option value="">All Categories</option>
                        {category_options}
                    </select>
                </div>
            </div>
            
            <div class="products-grid">
                {products_html}
            </div>
        </div>
        
        <script>
            function addToCart(productId) {{
                alert('Product ' + productId + ' added to cart!\\n\\nIn the MongoDB version, this will demonstrate:\\n- NoSQL injection vulnerabilities\\n- Cart manipulation attacks\\n- Session hijacking possibilities');
            }}
        </script>
    </body>
    </html>
    """

@app.get("/search")
async def search(q: str = ""):
    """Search products"""
    products = search_products(q)
    return {"query": q, "results": len(products), "products": products}

@app.get("/category/{category}")
async def category_filter(category: str):
    """Filter by category"""
    products = filter_by_category(category)
    return {"category": category, "results": len(products), "products": products}

def find_available_port(start_port=8083, max_attempts=10):
    """Find available port"""
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
    print("🛒 VulnShop Product Catalog Demo")
    print("=" * 50)
    print("📦 This demonstrates the complete product listings")
    print("🍃 Ready for MongoDB integration in the main vulnerable app")
    print("🎯 Shows what products will be available for security testing")
    
    port = find_available_port()
    if port:
        print(f"🌐 Starting demo server on http://localhost:{port}")
        uvicorn.run(app, host="127.0.0.1", port=port)
    else:
        print("❌ Could not find available port")
