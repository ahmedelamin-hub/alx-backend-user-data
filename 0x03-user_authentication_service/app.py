#!/usr/bin/env python3
"""
Flask application for user authentication and management.
"""
from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
AUTH = Auth()

@app.route("/", methods=["GET"])
def index() -> str:
    """Welcome page.
    
    Returns:
        str: JSON response welcoming the user.
    """
    return jsonify({"message": "Bienvenue"})

@app.route("/users", methods=["POST"])
def register_user():
    """Endpoint to register a new user.
    
    Returns:
        str: JSON response with user creation status.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400

@app.route("/sessions", methods=["POST"])
def log_in():
    """Endpoint for user login.
    
    Returns:
        str: JSON response with login status and session cookie.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_id", session_id)
    return response

@app.route("/sessions", methods=["DELETE"])
def log_out():
    """Endpoint to log out the user.
    
    Returns:
        str: Redirects to the welcome page after session destruction.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)

    if not user:
        abort(403)

    AUTH.destroy_session(user.id)
    return redirect(url_for('index'))

@app.route("/profile", methods=["GET"])
def user_profile():
    """Endpoint to fetch user profile details.
    
    Returns:
        str: JSON response with user email or error message.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)

    if not user:
        abort(403)

    return jsonify({"email": user.email})

@app.route("/reset_password", methods=["POST"])
def request_password_reset():
    """Endpoint to request a password reset token.
    
    Returns:
        str: JSON response with reset token or error message.
    """
    email = request.form.get("email")

    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token})
    except ValueError:
        abort(403)

@app.route("/reset_password", methods=["PUT"])
def reset_password():
    """Endpoint to update user password.
    
    Returns:
        str: JSON response with password update status or error message.
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")

    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"})
    except ValueError:
        abort(403)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
