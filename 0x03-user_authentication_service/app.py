#!/usr/bin/env python3
"""
Web application using Flask for authentication
"""
from auth import Auth
from flask import Flask, abort, jsonify, request, redirect, url_for

# Initialize the Flask application
app = Flask(__name__)
AUTH_HANDLER = Auth()  # Instantiate the authentication handler

@app.route("/", methods=["GET"])
def welcome() -> str:
    """Display a welcome message on the home page."""
    return jsonify({"message": "Welcome to the app"})

@app.route("/sessions", methods=["POST"])
def user_login():
    """Authenticate and log in a user."""
    email = request.form.get("email")
    password = request.form.get("password")
    if not AUTH_HANDLER.valid_login(email, password):
        return abort(401)  # Unauthorized access
    session_id = AUTH_HANDLER.create_session(email)
    response = jsonify({"email": email, "message": "Successfully logged in"})
    response.set_cookie("session_id", session_id)  # Set session ID in cookie
    return response

@app.route("/sessions", methods=["DELETE"])
def user_logout():
    """Log out the current user."""
    session_id = request.cookies.get("session_id")
    user = AUTH_HANDLER.get_user_from_session_id(session_id)
    if user is None:
        return abort(403)  # Forbidden if no valid user
    AUTH_HANDLER.destroy_session(user.id)
    return redirect(url_for("welcome"))

@app.route("/users", methods=["POST"])
def create_user():
    """Register a new user account."""
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        AUTH_HANDLER.register_user(email, password)
        return jsonify({"email": email, "message": "User created successfully"})
    except ValueError:
        return jsonify({"message": "Email already registered"}), 400

@app.route("/profile", methods=["GET"])
def show_profile() -> str:
    """Retrieve user profile details."""
    session_id = request.cookies.get("session_id")
    user = AUTH_HANDLER.get_user_from_session_id(session_id)
    if user is None:
        return abort(403)
    return jsonify({"email": user.email})

@app.route("/reset_password", methods=["POST"])
def request_reset_token() -> str:
    """Generate a password reset token for the user."""
    email = request.form.get("email")
    try:
        reset_token = AUTH_HANDLER.get_reset_password_token(email)
    except ValueError:
        return abort(403)
    return jsonify({"email": email, "reset_token": reset_token})

@app.route("/reset_password", methods=["PUT"])
def change_password():
    """Update user's password using reset token."""
    email = request.form.get("email")
    new_password = request.form.get("new_password")
    reset_token = request.form.get("reset_token")
    try:
        AUTH_HANDLER.update_password(reset_token, new_password)
    except ValueError:
        return abort(403)
    return jsonify({"email": email, "message": "Password has been updated"})

# Run the app on the designated host and port
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

