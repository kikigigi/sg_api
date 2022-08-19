from flask import Flask, request, jsonify
from flask_restful import Api, Resource
import re
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

# env variable
salt = 10

# set up mongodb
client = MongoClient("mongodb://db:27017")
# create a database
db = client.sgdb
# create users and games collection
users = db['users']
games = db['games']


# function for verify if a user's chosen password is valid
def check_valid_password(password):
    while True:
        if len(password) < 8:
            return 0
        elif re.search('[0-9]',password) is None:
            print("Make sure your password has a number in it")
            return 1
        elif re.search('[A-Z]',password) is None:
            print("Make sure your password has a capital letter in it")
            return 2
        else:
            print("Your password seems fine")
            return 3


# function for checking if an username has existed in the database
def check_username_existed(username):
    if users.count_documents({"username": username}) != 0:
        return True
    return False


# function for getting password
def verify_password(username, password):
    # username existed and check if password is correct
    existed_password = users.find_one({"username": username})["password"]
    hashed_password = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt(10))
    print(f"existed_password = {existed_password}, hashed_password = {hashed_password}")
    if existed_password == hashed_password:
        return True
    return False


# verify username and password
def verify_credentials(username, password):
    # check if the username existed
    existed_username = check_username_existed(username)
    if not existed_username:
        print("Stop 1")
        return False
    if verify_password(username, password):
        print("Stop 2")
        return True
    return False


def generate_msg(msg, state):
    return jsonify({"msg": msg,
                    "state": state})


class User(Resource):
    def post(self):
        # get posted data
        posted_data = request.get_json()

        # check existence of the posted_data
        if posted_data:
            username = posted_data["username"]
            password = posted_data["password"]
            print(f"username is {username}, password is {password}")
            # check if username existed
            username_existed = check_username_existed(username)
            if username_existed:
                return jsonify({'msg': f'{username} has existed!',
                                "status": 409}) # 409 conflict with resource

            # check if password is valid
            password_code = check_valid_password(password)
            if password_code == 0:
                return generate_msg("Password has to be at least 8 letter.", 400)
            elif password_code == 1:
                return generate_msg("Password requires at least one number.", 400)
            elif password_code == 2:
                generate_msg("Password requires at least one capital letter.", 400)

            # hash and store username and password
            hashed_password = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt(salt))
            users.insert_one({"username": username,
                              "password": hashed_password,
                              "scores": []
                              })
            return generate_msg("Registration successful.", 200)


class Game(Resource):
    # verify username and password
    def post(self):
        requested_data = request.get_json()
        # check the existence of the requested data

        game_id = requested_data["game_id"]
        attack = requested_data["attack"]
        resilience = requested_data["resilience"]
        response = requested_data["response"]

        games.insert_one({"game_id": game_id,
                              "attack": attack,
                              "resilience": resilience,
                              "response": response})

        return {"msg": "Game saved.",
                        "status": 200}


class Games(Resource):
    def get(self):
        the_games = games.find()
        the_list = []
        for game in the_games:
            the_list.append({"game_id": game["game_id"],
                            "attack": game["attack"],
                            "resilience": game["resilience"],
                            "response": game["response"]})
        return jsonify({"games": the_list,
                       "state": 200})


api.add_resource(User, "/register")
api.add_resource(Game, "/save")
api.add_resource(Games, "/games")


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

