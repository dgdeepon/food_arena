from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from bson import ObjectId
from bson import json_util
from datetime import date
import os
from dotenv import load_dotenv
from flask_cors import CORS
from pymongo import MongoClient

load_dotenv('.env')

app=Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
cors = CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

client = MongoClient(os.environ.get("MONGO_URL"))

# Dish
db = client[os.environ.get("MONGO_DB")]
collection=db["dish"]

# order
orderCollection=db["orders"]

#admin
adminCollection = db["admins"]
staffCollection = db["staffs"]

#user
userCollection= db["users"]



# getting all the dishes

@app.route('/dishes',methods=["GET"])
def getDish():
    data= collection.find({}).sort("name")
    mainData=json_util.dumps(data)
    return mainData


# adding more dishes

@app.route('/addDish',methods=["POST"])
@jwt_required()
def addDish():
    dish={
        "name":request.json["name"],
        "price":request.json["price"],
        "availability":request.json["availability"]
    }

    collection.insert_one(dish)
    return {"message":"Successfully added the dish."}



# updating the dishes

@app.route('/update/<id>',methods=["PUT"])
@jwt_required()
def updateNow(id):
    try:
        collection.update_one({"_id":ObjectId(id)},{"$set":request.json})
        return jsonify({"message":"dish is updated"})
    except:
        return jsonify({"message":"dish not found"})



# deleting dishes

@app.route('/delete/<id>',methods=["DELETE"])
@jwt_required()
def deleteeNow(id):
    try:
        collection.delete_one({'_id':ObjectId(id)})
        return jsonify({"message":"successfully deleted"})
    except:
        return jsonify({"message":"Dish not found"})
    

# getting orders
@app.route('/orders',methods=["GET"])
@jwt_required()
def getOrders():
    data=orderCollection.find().sort({"date"})
    mainData=json_util.dumps(data)
    return mainData


# taking orders
@app.route('/orderNow',methods=["POST"])
def orderNow():
    total=0
    for i in request.json['dishes']:
        total+=i["price"]

    order={
        "name":request.json["name"],
        "dishes":request.json["dishes"],
        "totalPrice":total,
        "status":"received",
        "date":date.today()
    }

    orderCollection.insert_one(order)
    return jsonify({"message":"order successful"})


# Change order status
@app.route('/orderStatus/<order_id>', methods=["PUT"])
@jwt_required()
def changeOrderStatus(order_id):
    new_status = request.json["status"]
    if new_status not in ["received", "ready for pickup","preparing", "delivered"]:
        return jsonify({"message": "Invalid order status"})

    result = orderCollection.update_one({"_id": ObjectId(order_id)}, {"$set": {"status": new_status}})
    if result.modified_count == 1:
        return jsonify({"message": "Order status updated"})
    else:
        return jsonify({"message": "Order not found"})
    


# Review all orders
@app.route('/reviewOrders', methods=["GET"])
@jwt_required()
def reviewOrders():
    received_orders = orderCollection.find({"status": "received"})
    ready_for_pickup = orderCollection.find({"status": "ready for pickup"})
    preparing = orderCollection.find({"status": "preparing"})
    delivered = orderCollection.find({"status": "delivered"})

    review_data = {
        "received_orders": json_util.dumps(received_orders),
        "ready for pickup": json_util.dumps(ready_for_pickup),
        "preparing": json_util.dumps(preparing),
        "deilvered": json_util.dumps(delivered)
    }

    return review_data


# Admin Registration
@app.route('/admin/register', methods=["POST"])
def registerAdmin():
    name = request.json["name"]
    email = request.json["email"]
    password = request.json["password"]

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    admin = {
        "name": name,
        "email": email,
        "password": hashed_password
    }

    adminCollection.insert_one(admin)

    return jsonify({"message": "Admin registered successfully"})

# Admin Login
@app.route('/admin/login', methods=["POST"])
def loginAdmin():
    email = request.json["email"]
    password = request.json["password"]

    admin = adminCollection.find_one({"email": email})
    if not admin or not bcrypt.check_password_hash(admin["password"], password):
        return jsonify({"message": "Invalid email or password"})

    access_token = create_access_token(identity=str(admin["_id"]))

    return jsonify({"access_token": access_token})

# Add Staff Credentials
@app.route('/admin/addStaff', methods=["POST"])
@jwt_required()
def addStaff():
    current_admin_id = get_jwt_identity()

    name = request.json["name"]
    email = request.json["email"]
    password = request.json["password"]

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    staff = {
        "admin_id": current_admin_id,
        "name": name,
        "email": email,
        "password": hashed_password
    }

    staffCollection.insert_one(staff)

    return jsonify({"message": "Staff added successfully"})

@app.route('/user/register',methods=["POST"])
def userRegister():
    name = request.json["name"]
    email = request.json["email"]
    password = request.json["password"]

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    user = {
        "name": name,
        "email": email,
        "password": hashed_password
    }

    userCollection.insert_one(user)

    return jsonify({"message": "User registered successfully"})


@app.route('/user/login',methods=["POST"])
def userLogin():
    email= request.json["email"]
    password = request.json["password"]

    user = userCollection.find_one({"email":email})

    if not user or not bcrypt.check_password_hash(user['password'],password):
        return jsonify({"message": "Invalid email or password"})

    access_token = create_access_token(identity=str(user["_id"]))

    return jsonify({"access_token": access_token})



if __name__=="__main__":
    app.run()