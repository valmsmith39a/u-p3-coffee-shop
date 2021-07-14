import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

"""
@TODO uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
!! Running this funciton will add one
"""
# db_drop_and_create_all()

# ROUTES

"""
@TODO: DONE: implement endpoint
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
"""


@app.route("/drinks")
def get_drinks():
    try:
        drinks = Drink.query.all()
        return jsonify({"success": True, "drinks": [drink.short() for drink in drinks]})
    except:
        abort(422)


"""
@TODO: DONE: implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
"""
@app.route("/drinks-details")
@requires_auth("get:drinks-detail")
def get_drinks_details(jwt):
    try:
        drinks = Drink.query.all()
        return jsonify({"success": True, "drinks": [drink.long() for drink in drinks]})
    except:
        abort(422)


"""
@TODO implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
"""


@app.route("/drinks", methods=["POST"])
@requires_auth("post:drinks")
def create_drink(jwt):
    try:
        body = request.get_json()
        title = body.get("title", None)
        recipe = json.dumps(body.get("recipe", None))

        if title is None or recipe is None:
            abort(400)

        new_drink = Drink(title=title, recipe=recipe)
        new_drink.insert()

        drinks = Drink.query.all()

        return jsonify({
            "success": True,
            "drinks": [drink.long() for drink in drinks]
        })

    except:
        abort(422)


"""
@TODO:DONE: implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
"""

@app.route("/drinks/<int:id>", methods=["PATCH"])
@requires_auth("patch:drinks")
def update_drink(id):
    try:
        if id is None:
            abort(404)

        drink = Drink.query.filter(Drink.id == id).one_or_none()
        new_drink_data = request.get_json()
        title = json.dumps(new_drink_data["title"])
        recipe = json.dumps(new_drink_data["recipe"])

        if "title" in new_drink_data:
            drink.title = title

        if "recipe" in new_drink_data:
            drink.recipe = recipe 
        
        drink.update()

        return jsonify({
            "success": True,
            "drink": [drink.long()]
        })

    except:
        abort(422)

"""
@TODO implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
"""
@app.route("/drinks/<int:id>", methods=["DELETE"])
@requires_auth("delete:drinks")
def delete_drink(id):
    try:
        drink = Drink.query.filter(Drink.id == id).one_or_none()
        
        if drink is None:
            abort(422)

        drink.delete()

        return jsonify({
            "success": True,
            "delete": id
        })

    except:
        abort(422)


# Error Handling
"""
Example error handling for unprocessable entity
"""
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({"success": False, "error": 422, "message": "unprocessable"}), 422


"""
@TODO: DONE: implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False,
                    "error": 404,
                    "message": "resource not found"
                    }), 404

"""
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"success": False, "error": 400, "message": "bad request"}), 400
    
"""
@TODO: DONE: implement error handler for 404
    error handler should conform to general task above
"""
@app.errorhandler(404)
def file_not_found(error):
    return jsonify({"success": False, "error": 404, "message": "file not found"}), 404

"""
@TODO: DONE: implement error handler for AuthError
    error handler should conform to general task above
"""
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code
