#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')
        bio = data.get('bio')
        image_url = data.get('image_url')

        if not username or not password:
            return jsonify({"error": "Username and password are required."}), 422

        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password_hash=hashed_password, bio=bio, image_url=image_url)

        try:
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id

            return jsonify({
                "id": new_user.id,
                "username": new_user.username,
                "image_url": new_user.image_url,
                "bio": new_user.bio
            }), 201

        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "Username already exists."}), 422

        except Exception as e:
            return jsonify({"error": str(e)}), 500

class CheckSession(Resource):
    def get(self):
        try:
            user_id = session.get('user_id')

            if not user_id:
                return jsonify({"error": "Unauthorized"}), 401

            user = User.query.get(user_id)

            if not user:
                return jsonify({"error": "User not found."}), 401

            return jsonify({
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500

class Login(Resource):
    def post(self):
        data = request.get_json()

        try:
            username = data.get('username')
            password = data.get('password')

            user = User.query.filter_by(username=username).first()

            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id

                return jsonify({
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }), 200
            else:
                return jsonify({"error": "Invalid username or password."}), 401

        except Exception as e:
            return jsonify({"error": str(e)}), 500

class Logout(Resource):
    def delete(self):
        try:
            user_id = session.get('user_id')

            if not user_id:
                return jsonify({"error": "Unauthorized"}), 401

            session.pop('user_id', None)
            return '', 204

        except Exception as e:
            return jsonify({"error": str(e)}), 500

class RecipeIndex(Resource):
    def get(self):
        try:
            user_id = session.get('user_id')

            if not user_id:
                return jsonify({"error": "Unauthorized"}), 401

            recipes = Recipe.query.all()
            recipes_list = [{
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio": recipe.user.bio
                }
            } for recipe in recipes]

            return jsonify(recipes_list), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def post(self):
        try:
            user_id = session.get('user_id')

            if not user_id:
                return jsonify({"error": "Unauthorized"}), 401

            data = request.get_json()

            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')

            if not title or not instructions or not minutes_to_complete:
                return jsonify({"error": "All fields are required."}), 422

            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )

            try:
                db.session.add(new_recipe)
                db.session.commit()

                return jsonify({
                    "title": new_recipe.title,
                    "instructions": new_recipe.instructions,
                    "minutes_to_complete": new_recipe.minutes_to_complete,
                    "user": {
                        "id": new_recipe.user.id,
                        "username": new_recipe.user.username,
                        "image_url": new_recipe.user.image_url,
                        "bio": new_recipe.user.bio
                    }
                }), 201

            except IntegrityError:
                db.session.rollback()
                return jsonify({"error": "Error saving recipe."}), 422

        except Exception as e:
            return jsonify({"error": str(e)}), 500

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
