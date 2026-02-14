"""
MongoDB Setup Script for VulnShop
This script sets up MongoDB for the vulnerable application
"""

import pymongo
from pymongo import MongoClient
from bson import ObjectId
import datetime
import sys

def check_mongodb_connection():
    """Check if MongoDB is running and accessible"""
    try:
        client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
        client.server_info()  # This will raise an exception if MongoDB is not accessible
        print("✅ MongoDB is running and accessible")
        return client
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        print("💡 Make sure MongoDB is installed and running:")
        print("   - Windows: Run 'mongod' in a terminal")
        print("   - macOS: Run 'brew services start mongodb-community'")
        print("   - Linux: Run 'sudo systemctl start mongod'")
        return None

def setup_vulnshop_database():
    """Set up the VulnShop database with initial data"""
    client = check_mongodb_connection()
    if not client:
        return False
    
    try:
        # Get database
        db = client["vulnshop"]
        
        # Drop existing collections for fresh start
        print("🗑️ Dropping existing collections...")
        db.users.drop()
        db.products.drop()
        db.orders.drop()
        
        # Create users collection with vulnerable data
        print("👥 Creating users collection...")
        users_data = [
            {
                "_id": ObjectId(),
                "username": "admin",
                "password": "admin123",  # Plain text password (vulnerable!)
                "email": "admin@vulnshop.com",
                "is_admin": True,
                "created_at": datetime.datetime.utcnow(),
                "profile": {
                    "first_name": "System",
                    "last_name": "Administrator",
                    "phone": "+1-555-0001"
                }
            },
            {
                "_id": ObjectId(),
                "username": "user",
                "password": "password",  # Plain text password (vulnerable!)
                "email": "user@vulnshop.com",
                "is_admin": False,
                "created_at": datetime.datetime.utcnow(),
                "profile": {
                    "first_name": "Test",
                    "last_name": "User",
                    "phone": "+1-555-0002"
                }
            },
            {
                "_id": ObjectId(),
                "username": "guest",
                "password": "guest",  # Plain text password (vulnerable!)
                "email": "guest@vulnshop.com",
                "is_admin": False,
                "created_at": datetime.datetime.utcnow(),
                "profile": {
                    "first_name": "Guest",
                    "last_name": "Account",
                    "phone": "+1-555-0003"
                }
            }
        ]
        
        db.users.insert_many(users_data)
        print(f"✅ Created {len(users_data)} users")
        
        # Create comprehensive products collection for VulnShop
        products_data = [
            {
                "_id": ObjectId(),
                "name": "Gaming Laptop Pro X1",
                "price": 1899.99,
                "description": "Ultimate gaming laptop with RTX 4080, 32GB RAM, 1TB SSD",
                "category": "Electronics",
                "subcategory": "Laptops",
                "brand": "TechMaster",
                "stock": 15,
                "rating": 4.8,
                "features": ["RTX 4080 GPU", "32GB DDR5 RAM", "1TB NVMe SSD", "17.3 inch 4K Display"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Smartphone Pro Max 256GB",
                "price": 1199.99,
                "description": "Latest flagship smartphone with triple camera system and 5G",
                "category": "Electronics",
                "subcategory": "Smartphones",
                "brand": "PhoneTech",
                "stock": 42,
                "rating": 4.6,
                "features": ["Triple Camera", "5G Ready", "256GB Storage", "Fast Charging"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Wireless Noise-Canceling Headphones",
                "price": 299.99,
                "description": "Premium wireless headphones with active noise cancellation",
                "category": "Audio",
                "subcategory": "Headphones",
                "brand": "AudioElite",
                "stock": 67,
                "rating": 4.7,
                "features": ["Active Noise Cancellation", "30hr Battery", "Bluetooth 5.0", "Quick Charge"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "4K Smart TV 65 inch",
                "price": 799.99,
                "description": "Ultra HD 4K Smart TV with HDR support and streaming apps",
                "category": "Electronics",
                "subcategory": "Televisions",
                "brand": "ViewMaster",
                "stock": 23,
                "rating": 4.5,
                "features": ["4K Ultra HD", "HDR Support", "Smart TV Platform", "Voice Control"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Professional DSLR Camera Kit",
                "price": 1299.99,
                "description": "Professional DSLR camera with 24MP sensor and 4K video",
                "category": "Electronics",
                "subcategory": "Cameras",
                "brand": "PhotoPro",
                "stock": 18,
                "rating": 4.9,
                "features": ["24MP Sensor", "4K Video", "Lens Kit Included", "Weather Sealed"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Smart Fitness Watch",
                "price": 249.99,
                "description": "Advanced fitness tracking smartwatch with GPS and heart rate monitor",
                "category": "Wearables",
                "subcategory": "Smartwatches",
                "brand": "FitTracker",
                "stock": 89,
                "rating": 4.4,
                "features": ["GPS Tracking", "Heart Rate Monitor", "7-day Battery", "Water Resistant"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Mechanical Gaming Keyboard RGB",
                "price": 159.99,
                "description": "Mechanical gaming keyboard with RGB backlighting and Cherry MX switches",
                "category": "Accessories",
                "subcategory": "Keyboards",
                "brand": "GameGear",
                "stock": 156,
                "rating": 4.6,
                "features": ["Cherry MX Switches", "RGB Backlighting", "Programmable Keys", "Aluminum Frame"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Wireless Gaming Mouse",
                "price": 89.99,
                "description": "High-precision wireless gaming mouse with 16000 DPI sensor",
                "category": "Accessories",
                "subcategory": "Mice",
                "brand": "GameGear",
                "stock": 234,
                "rating": 4.5,
                "features": ["16000 DPI Sensor", "Wireless", "Customizable Buttons", "RGB Lighting"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Bluetooth Portable Speaker",
                "price": 79.99,
                "description": "Waterproof portable Bluetooth speaker with 360-degree sound",
                "category": "Audio",
                "subcategory": "Speakers",
                "brand": "SoundWave",
                "stock": 78,
                "rating": 4.3,
                "features": ["360° Sound", "Waterproof", "12hr Battery", "Voice Assistant"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "USB-C Hub Multi-Port Adapter",
                "price": 49.99,
                "description": "7-in-1 USB-C hub with HDMI, USB 3.0, and SD card reader",
                "category": "Accessories",
                "subcategory": "Adapters",
                "brand": "ConnectPro",
                "stock": 189,
                "rating": 4.2,
                "features": ["7-in-1 Design", "HDMI 4K Output", "Fast Charging", "Compact Design"],
                "created_at": datetime.datetime.utcnow()
            },
            # NEW PRODUCTS - 10 Additional Items
            {
                "_id": ObjectId(),
                "name": "Wireless Charging Pad Pro",
                "price": 39.99,
                "description": "Fast wireless charging pad with LED indicators and phone stand",
                "category": "Accessories",
                "subcategory": "Chargers",
                "brand": "ChargeTech",
                "stock": 145,
                "rating": 4.3,
                "features": ["15W Fast Charging", "LED Status", "Phone Stand", "Case Friendly"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Gaming Chair Ergonomic Pro",
                "price": 299.99,
                "description": "Professional gaming chair with lumbar support and RGB lighting",
                "category": "Furniture",
                "subcategory": "Gaming Chairs",
                "brand": "ComfortGame",
                "stock": 34,
                "rating": 4.7,
                "features": ["Lumbar Support", "RGB Lighting", "Adjustable Height", "Memory Foam"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Webcam 4K Ultra HD",
                "price": 149.99,
                "description": "4K webcam with auto-focus and noise-canceling microphone",
                "category": "Electronics",
                "subcategory": "Webcams",
                "brand": "StreamMaster",
                "stock": 78,
                "rating": 4.5,
                "features": ["4K Recording", "Auto Focus", "Noise Canceling Mic", "USB Plug & Play"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Portable SSD 1TB",
                "price": 179.99,
                "description": "Ultra-fast portable SSD with USB-C connectivity",
                "category": "Storage",
                "subcategory": "External Drives",
                "brand": "SpeedStore",
                "stock": 167,
                "rating": 4.8,
                "features": ["1TB Capacity", "USB-C 3.2", "540MB/s Speed", "Shock Resistant"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "VR Headset Elite",
                "price": 599.99,
                "description": "Advanced VR headset with 4K display and spatial tracking",
                "category": "Electronics",
                "subcategory": "VR Headsets",
                "brand": "VirtualTech",
                "stock": 28,
                "rating": 4.6,
                "features": ["4K Per Eye", "120Hz Refresh", "Spatial Tracking", "Wireless"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Electric Standing Desk",
                "price": 449.99,
                "description": "Height-adjustable electric standing desk with memory presets",
                "category": "Furniture",
                "subcategory": "Desks",
                "brand": "ErgoWork",
                "stock": 19,
                "rating": 4.4,
                "features": ["Electric Height Adjust", "Memory Presets", "Cable Management", "48x30 inch"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Drone 4K Camera Pro",
                "price": 899.99,
                "description": "Professional drone with 4K camera and GPS auto-return",
                "category": "Electronics",
                "subcategory": "Drones",
                "brand": "SkyMaster",
                "stock": 41,
                "rating": 4.7,
                "features": ["4K Camera", "GPS Auto Return", "30min Flight Time", "Obstacle Avoidance"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Smart Home Hub",
                "price": 129.99,
                "description": "Central smart home hub with voice control and app integration",
                "category": "Smart Home",
                "subcategory": "Hubs",
                "brand": "SmartLife",
                "stock": 93,
                "rating": 4.2,
                "features": ["Voice Control", "Multi-Protocol", "App Integration", "Local Processing"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Mechanical Keyboard Full Size",
                "price": 189.99,
                "description": "Full-size mechanical keyboard with hot-swappable switches",
                "category": "Accessories",
                "subcategory": "Keyboards",
                "brand": "TypeMaster",
                "stock": 112,
                "rating": 4.9,
                "features": ["Hot-Swappable", "RGB Per Key", "Aluminum Frame", "USB-C Detachable"],
                "created_at": datetime.datetime.utcnow()
            },
            {
                "_id": ObjectId(),
                "name": "Smart Security Camera",
                "price": 89.99,
                "description": "WiFi security camera with night vision and motion detection",
                "category": "Smart Home",
                "subcategory": "Security",
                "brand": "SecureWatch",
                "stock": 156,
                "rating": 4.1,
                "features": ["1080p HD", "Night Vision", "Motion Detection", "Cloud Storage"],
                "created_at": datetime.datetime.utcnow()
            }
        ]
        
        db.products.insert_many(products_data)
        print(f"✅ Created {len(products_data)} products")
        
        # Create orders collection (initially empty)
        print("📦 Creating orders collection...")
        db.orders.create_index([("user_id", 1), ("created_at", -1)])
        print("✅ Orders collection created with indexes")
        
        # Create indexes for better performance and testing
        print("🔍 Creating database indexes...")
        db.users.create_index("username", unique=True)
        db.users.create_index("email")
        db.products.create_index("name")
        db.products.create_index("category")
        db.products.create_index("price")
        
        print("✅ Database indexes created")
        
        # Print database statistics
        print("\n📊 Database Statistics:")
        print(f"   Users: {db.users.count_documents({})}")
        print(f"   Products: {db.products.count_documents({})}")
        print(f"   Orders: {db.orders.count_documents({})}")
        
        print("\n🎯 Vulnerable Test Data Created!")
        print("   Database: vulnshop")
        print("   Collections: users, products, orders")
        print("   MongoDB URL: mongodb://localhost:27017/")
        
        print("\n👤 Test Accounts:")
        for user in users_data:
            role = "Admin" if user["is_admin"] else "User"
            print(f"   {role}: {user['username']} / {user['password']}")
        
        print("\n⚠️ SECURITY WARNING:")
        print("   This database contains intentional vulnerabilities!")
        print("   - Plain text passwords")
        print("   - No input validation")
        print("   - NoSQL injection vulnerable")
        print("   - FOR TESTING PURPOSES ONLY!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error setting up database: {e}")
        return False
    finally:
        client.close()

def test_nosql_injections():
    """Test common NoSQL injection patterns"""
    client = check_mongodb_connection()
    if not client:
        return False
    
    try:
        db = client["vulnshop"]
        
        print("\n🔍 Testing NoSQL Injection Vulnerabilities:")
        
        # Test 1: Authentication bypass with $ne
        print("\n1. Testing authentication bypass with $ne operator:")
        query1 = {"username": {"$ne": None}, "password": {"$ne": None}}
        result1 = db.users.find_one(query1)
        if result1:
            print(f"   ✅ Bypassed authentication! Found user: {result1['username']}")
        
        # Test 2: Data extraction with regex
        print("\n2. Testing data extraction with regex:")
        query2 = {"username": {"$regex": ".*"}}
        result2 = list(db.users.find(query2, {"password": 1, "username": 1}))
        print(f"   ✅ Extracted {len(result2)} user credentials")
        
        # Test 3: JavaScript injection with $where
        print("\n3. Testing JavaScript injection with $where:")
        query3 = {"$where": "this.price > 500"}
        result3 = list(db.products.find(query3))
        print(f"   ✅ Found {len(result3)} products using JavaScript injection")
        
        # Test 4: Operator injection for privilege escalation
        print("\n4. Testing privilege escalation:")
        query4 = {"is_admin": {"$ne": False}}
        result4 = list(db.users.find(query4))
        print(f"   ✅ Found {len(result4)} admin accounts")
        
        print("\n⚠️ All injection tests successful! Database is vulnerable as intended.")
        return True
        
    except Exception as e:
        print(f"❌ Error testing injections: {e}")
        return False
    finally:
        client.close()

if __name__ == "__main__":
    print("🍃 VulnShop MongoDB Setup Script")
    print("=" * 50)
    
    # Setup database
    if setup_vulnshop_database():
        print("\n✅ Database setup completed successfully!")
        
        # Run injection tests
        if "--test" in sys.argv:
            test_nosql_injections()
    else:
        print("\n❌ Database setup failed!")
        exit(1)
    
    print("\n🚀 You can now run the vulnerable application:")
    print("   python vulnerable_app_mongodb.py")
