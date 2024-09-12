#!/usr/bin/env python3
"""
Web application with user authentication
"""
from flask import Flask, request, jsonify, abort, redirect, url_for
from auth import AuthService

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True
auth_service = AuthService()

@app.route("/")
def welcome():
    """Welcome route."""
    return jsonify({"message": "Welcome to our service!"})

@app.route("/sessions", methods=["POST"])
def login_user():
    """Handle user login."""
    email = request.form.get("email")
    password = request.form.get("password")
    if not auth_service.validate_login(email, password):
        abort(401)
    session_id = auth_service.generate_session(email)
    response = jsonify({"email": email, "message": "Successfully logged in."})
    response.set_cookie("session_id", session_id)
    return response

@app.route("/sessions", methods=["DELETE"])
def logout_user():
    """Handle user logout."""
    session_id = request.cookies.get("session_id")
    user = auth_service.fetch_user_by_session(session_id)
    if not user:
        abort(403)
    auth_service.terminate_session(user.id)
    return redirect(url_for("welcome"))

@app.route("/users", methods=["POST"])
def create_user():
    """Register a new user."""
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        user = auth_service.register(email, password)
        return jsonify({"email": email, "message": "User created successfully."})
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

@app.route("/profile")
def get_profile():
    """Fetch the user's profile data."""
    session_id = request.cookies.get("session_id")
    user = auth_service.fetch_user_by_session(session_id)
    if not user:
        abort(403)
    return jsonify({"email": user.email})

@app.route("/reset_password", methods=["POST"])
def reset_password():
    """Request a password reset token."""
    email = request.form.get("email")
    try:
        token = auth_service.generate_password_reset_token(email)
        return jsonify({"email": email, "reset_token": token})
    except ValueError:
        abort(403)

@app.route("/reset_password", methods=["PUT"])
def change_password():
    """Update user password using a reset token."""
    email = request.form.get("email")
    new_password = request.form.get("new_password")
    reset_token = request.form.get("reset_token")
    try:
        auth_service.modify_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated successfully."})
    except ValueError:
        abort(403)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
