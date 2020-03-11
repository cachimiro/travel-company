import os
from flask import Flask, render_template, redirect, request, url_for
from flask_pymongo import PyMongo
from bson.objectid import ObjectId 
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MONGO_DBNAME"] = 'travel'
app.config["MONGO_URI"] = 'mongodb+srv://root:Johann@myfirstcluster-ugp0n.mongodb.net/travel?retryWrites=true&w=majority'

mongo = PyMongo(app)
app.secret_key = "cachimiro"

@app.route('/')
def index():
    return render_template("index.html", Travel=mongo.db.pais.find())




if __name__ == '__main__':
    app.run(host=os.environ.get('IP'),
            port=int(os.environ.get('PORT')),
            debug=True)