"""
VulnShop Product Catalog - Standalone Version
Works with or without MongoDB
"""

import json
from datetime import datetime

# Sample product data for VulnShop (fallback if MongoDB is not available)
SAMPLE_PRODUCTS = [
    {
        "_id": "507f1f77bcf86cd799439011",
        "name": "Gaming Laptop Pro X1",
        "price": 1899.99,
        "description": "Ultimate gaming laptop with RTX 4080, 32GB RAM, 1TB SSD",
        "category": "Electronics",
        "subcategory": "Laptops",
        "brand": "TechMaster",
        "stock": 15,
        "rating": 4.8,
        "features": ["RTX 4080 GPU", "32GB DDR5 RAM", "1TB NVMe SSD", "17.3 inch 4K Display"],
        "created_at": "2025-09-06T10:00:00"
    },
    {
        "_id": "507f1f77bcf86cd799439012",
        "name": "Smartphone Pro Max 256GB",
        "price": 1199.99,
        "description": "Latest flagship smartphone with triple camera system and 5G",
        "category": "Electronics",
        "subcategory": "Smartphones",
        "brand": "PhoneTech",
        "stock": 42,
        "rating": 4.6,
        "features": ["Triple Camera", "5G Ready", "256GB Storage", "Fast Charging"],
        "created_at": "2025-09-06T10:15:00"
    },
    {
        "_id": "507f1f77bcf86cd799439013",
        "name": "Wireless Noise-Canceling Headphones",
        "price": 299.99,
        "description": "Premium wireless headphones with active noise cancellation",
        "category": "Audio",
        "subcategory": "Headphones", 
        "brand": "AudioElite",
        "stock": 67,
        "rating": 4.7,
        "features": ["Active Noise Cancellation", "30hr Battery", "Bluetooth 5.0", "Quick Charge"],
        "created_at": "2025-09-06T10:30:00"
    },
    {
        "_id": "507f1f77bcf86cd799439014",
        "name": "4K Smart TV 65 inch",
        "price": 799.99,
        "description": "Ultra HD 4K Smart TV with HDR support and streaming apps",
        "category": "Electronics",
        "subcategory": "Televisions",
        "brand": "ViewMaster",
        "stock": 23,
        "rating": 4.5,
        "features": ["4K Ultra HD", "HDR Support", "Smart TV Platform", "Voice Control"],
        "created_at": "2025-09-06T10:45:00"
    },
    {
        "_id": "507f1f77bcf86cd799439015",
        "name": "Professional DSLR Camera Kit",
        "price": 1299.99,
        "description": "Professional DSLR camera with 24MP sensor and 4K video",
        "category": "Electronics",
        "subcategory": "Cameras",
        "brand": "PhotoPro",
        "stock": 18,
        "rating": 4.9,
        "features": ["24MP Sensor", "4K Video", "Lens Kit Included", "Weather Sealed"],
        "created_at": "2025-09-06T11:00:00"
    },
    {
        "_id": "507f1f77bcf86cd799439016",
        "name": "Smart Fitness Watch",
        "price": 249.99,
        "description": "Advanced fitness tracking smartwatch with GPS and heart rate monitor",
        "category": "Wearables",
        "subcategory": "Smartwatches",
        "brand": "FitTracker",
        "stock": 89,
        "rating": 4.4,
        "features": ["GPS Tracking", "Heart Rate Monitor", "7-day Battery", "Water Resistant"],
        "created_at": "2025-09-06T11:15:00"
    },
    {
        "_id": "507f1f77bcf86cd799439017",
        "name": "Mechanical Gaming Keyboard RGB",
        "price": 159.99,
        "description": "Mechanical gaming keyboard with RGB backlighting and Cherry MX switches",
        "category": "Accessories",
        "subcategory": "Keyboards",
        "brand": "GameGear",
        "stock": 156,
        "rating": 4.6,
        "features": ["Cherry MX Switches", "RGB Backlighting", "Programmable Keys", "Aluminum Frame"],
        "created_at": "2025-09-06T11:30:00"
    },
    {
        "_id": "507f1f77bcf86cd799439018",
        "name": "Wireless Gaming Mouse",
        "price": 89.99,
        "description": "High-precision wireless gaming mouse with 16000 DPI sensor",
        "category": "Accessories", 
        "subcategory": "Mice",
        "brand": "GameGear",
        "stock": 234,
        "rating": 4.5,
        "features": ["16000 DPI Sensor", "Wireless", "Customizable Buttons", "RGB Lighting"],
        "created_at": "2025-09-06T11:45:00"
    },
    {
        "_id": "507f1f77bcf86cd799439019",
        "name": "Bluetooth Portable Speaker",
        "price": 79.99,
        "description": "Waterproof portable Bluetooth speaker with 360-degree sound",
        "category": "Audio",
        "subcategory": "Speakers",
        "brand": "SoundWave",
        "stock": 78,
        "rating": 4.3,
        "features": ["360° Sound", "Waterproof", "12hr Battery", "Voice Assistant"],
        "created_at": "2025-09-06T12:00:00"
    },
    {
        "_id": "507f1f77bcf86cd799439020",
        "name": "USB-C Hub Multi-Port Adapter",
        "price": 49.99,
        "description": "7-in-1 USB-C hub with HDMI, USB 3.0, and SD card reader",
        "category": "Accessories",
        "subcategory": "Adapters",
        "brand": "ConnectPro",
        "stock": 189,
        "rating": 4.2,
        "features": ["7-in-1 Design", "HDMI 4K Output", "Fast Charging", "Compact Design"],
        "created_at": "2025-09-06T12:15:00"
    },
    {
        "_id": "507f1f77bcf86cd799439021",
        "name": "Wireless Charging Pad Pro",
        "price": 39.99,
        "description": "Fast wireless charging pad with LED indicators and phone stand",
        "category": "Accessories",
        "subcategory": "Chargers",
        "brand": "ChargeTech",
        "stock": 145,
        "rating": 4.3,
        "features": ["15W Fast Charging", "LED Status", "Phone Stand", "Case Friendly"],
        "created_at": "2025-09-06T12:30:00"
    },
    {
        "_id": "507f1f77bcf86cd799439022",
        "name": "Gaming Chair Ergonomic Pro",
        "price": 299.99,
        "description": "Professional gaming chair with lumbar support and RGB lighting",
        "category": "Furniture",
        "subcategory": "Gaming Chairs",
        "brand": "ComfortGame",
        "stock": 34,
        "rating": 4.7,
        "features": ["Lumbar Support", "RGB Lighting", "Adjustable Height", "Memory Foam"],
        "created_at": "2025-09-06T12:45:00"
    },
    {
        "_id": "507f1f77bcf86cd799439023",
        "name": "Webcam 4K Ultra HD",
        "price": 149.99,
        "description": "4K webcam with auto-focus and noise-canceling microphone",
        "category": "Electronics",
        "subcategory": "Webcams",
        "brand": "StreamMaster",
        "stock": 78,
        "rating": 4.5,
        "features": ["4K Recording", "Auto Focus", "Noise Canceling Mic", "USB Plug & Play"],
        "created_at": "2025-09-06T13:00:00"
    },
    {
        "_id": "507f1f77bcf86cd799439024",
        "name": "Portable SSD 1TB",
        "price": 179.99,
        "description": "Ultra-fast portable SSD with USB-C connectivity",
        "category": "Storage",
        "subcategory": "External Drives",
        "brand": "SpeedStore",
        "stock": 167,
        "rating": 4.8,
        "features": ["1TB Capacity", "USB-C 3.2", "540MB/s Speed", "Shock Resistant"],
        "created_at": "2025-09-06T13:15:00"
    },
    {
        "_id": "507f1f77bcf86cd799439025",
        "name": "VR Headset Elite",
        "price": 599.99,
        "description": "Advanced VR headset with 4K display and spatial tracking",
        "category": "Electronics",
        "subcategory": "VR Headsets",
        "brand": "VirtualTech",
        "stock": 28,
        "rating": 4.6,
        "features": ["4K Per Eye", "120Hz Refresh", "Spatial Tracking", "Wireless"],
        "created_at": "2025-09-06T13:30:00"
    },
    {
        "_id": "507f1f77bcf86cd799439026",
        "name": "Electric Standing Desk",
        "price": 449.99,
        "description": "Height-adjustable electric standing desk with memory presets",
        "category": "Furniture",
        "subcategory": "Desks",
        "brand": "ErgoWork",
        "stock": 19,
        "rating": 4.4,
        "features": ["Electric Height Adjust", "Memory Presets", "Cable Management", "48x30 inch"],
        "created_at": "2025-09-06T13:45:00"
    },
    {
        "_id": "507f1f77bcf86cd799439027",
        "name": "Drone 4K Camera Pro",
        "price": 899.99,
        "description": "Professional drone with 4K camera and GPS auto-return",
        "category": "Electronics",
        "subcategory": "Drones",
        "brand": "SkyMaster",
        "stock": 41,
        "rating": 4.7,
        "features": ["4K Camera", "GPS Auto Return", "30min Flight Time", "Obstacle Avoidance"],
        "created_at": "2025-09-06T14:00:00"
    },
    {
        "_id": "507f1f77bcf86cd799439028",
        "name": "Smart Home Hub",
        "price": 129.99,
        "description": "Central smart home hub with voice control and app integration",
        "category": "Smart Home",
        "subcategory": "Hubs",
        "brand": "SmartLife",
        "stock": 93,
        "rating": 4.2,
        "features": ["Voice Control", "Multi-Protocol", "App Integration", "Local Processing"],
        "created_at": "2025-09-06T14:15:00"
    },
    {
        "_id": "507f1f77bcf86cd799439029",
        "name": "Mechanical Keyboard Full Size",
        "price": 189.99,
        "description": "Full-size mechanical keyboard with hot-swappable switches",
        "category": "Accessories",
        "subcategory": "Keyboards",
        "brand": "TypeMaster",
        "stock": 112,
        "rating": 4.9,
        "features": ["Hot-Swappable", "RGB Per Key", "Aluminum Frame", "USB-C Detachable"],
        "created_at": "2025-09-06T14:30:00"
    },
    {
        "_id": "507f1f77bcf86cd799439030",
        "name": "Smart Security Camera",
        "price": 89.99,
        "description": "WiFi security camera with night vision and motion detection",
        "category": "Smart Home",
        "subcategory": "Security",
        "brand": "SecureWatch",
        "stock": 156,
        "rating": 4.1,
        "features": ["1080p HD", "Night Vision", "Motion Detection", "Cloud Storage"],
        "created_at": "2025-09-06T14:45:00"
    }
]

def get_products():
    """Get all products"""
    return SAMPLE_PRODUCTS

def search_products(query):
    """Search products by name, description, or brand"""
    if not query:
        return SAMPLE_PRODUCTS
    
    query_lower = query.lower()
    results = []
    
    for product in SAMPLE_PRODUCTS:
        if (query_lower in product['name'].lower() or 
            query_lower in product['description'].lower() or 
            query_lower in product['brand'].lower()):
            results.append(product)
    
    return results

def filter_by_category(category):
    """Filter products by category"""
    if not category:
        return SAMPLE_PRODUCTS
    
    return [p for p in SAMPLE_PRODUCTS if p['category'].lower() == category.lower()]

def get_categories():
    """Get all unique categories"""
    categories = set()
    for product in SAMPLE_PRODUCTS:
        categories.add(product['category'])
    return sorted(list(categories))

def generate_product_html(product):
    """Generate HTML for a single product"""
    features_html = ""
    for feature in product.get('features', []):
        features_html += f'<span class="feature-tag">{feature}</span>'
    
    return f"""
    <div class="product-card">
        <div class="product-image">
            <div class="image-placeholder">📷</div>
        </div>
        <div class="product-info">
            <h3 class="product-name">{product['name']}</h3>
            <p class="product-brand">{product['brand']}</p>
            <p class="product-price">${product['price']:.2f}</p>
            <p class="product-description">{product['description']}</p>
            <div class="product-features">
                {features_html}
            </div>
            <div class="product-meta">
                <span class="stock">Stock: {product['stock']}</span>
                <span class="rating">⭐ {product['rating']}</span>
                <span class="category">{product['category']}</span>
            </div>
            <button class="add-to-cart-btn" onclick="addToCart('{product['_id']}')">Add to Cart</button>
        </div>
    </div>
    """

if __name__ == "__main__":
    print("🛒 VulnShop Product Catalog")
    print(f"📊 Total Products: {len(SAMPLE_PRODUCTS)}")
    print(f"🏪 Categories: {', '.join(get_categories())}")
    
    # Test search
    gaming_products = search_products("gaming")
    print(f"🎮 Gaming Products: {len(gaming_products)}")
    
    # Test category filter
    electronics = filter_by_category("Electronics")
    print(f"💻 Electronics: {len(electronics)}")
