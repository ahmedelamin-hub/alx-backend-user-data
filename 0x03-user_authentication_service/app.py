#!/usr/bin/env python3
"""
Flask app providing authentication routes.
"""
from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth

app = Flask(__name__)
AUTH = Auth()
app.url_map.strict_slashes = False


@app.route("/", methods=["GET"])
def welcome():
    """Welcome endpoint.

    Returns:
        JSON: A welcome message.
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def create_user():
    """Register a new user.

    Form Data:
        - email: The user's email.
        - password: The user's password.

    Returns:
        JSON: Email and message if created or error if email exists.
    """
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """Login a user.

    Form Data:
        - email: The user's email.
        - password: The user's password.

    Returns:
        JSON: Email and message on success, 401 error on failure.
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
def logout():
    """Log out a user.

    Returns:
        Redirect: Redirects to the home page.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect(url_for("welcome"))


@app.route("/profile", methods=["GET"])
def profile():
    """Get the profile of a logged-in user.

    Returns:
        JSON: User's email or 403 error if session is invalid.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    return jsonify({"email": user.email})


@app.route("/reset_password", methods=["POST"])
def reset_password():
    """Request a password reset token.

    Form Data:
        - email: The user's email.

    Returns:
        JSON: Email and reset token or 403 error.
    """
    email = request.form.get("email")
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token})
    except ValueError:
        abort(403)


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """Update a user's password using a reset token.

    Form Data:
        - email: The user's email.
        - reset_token: The reset token.
        - new_password: The new password.

    Returns:
        JSON: Email and success message or 403 error.
    """
    email = request.form.get("email")
    new_password = request.form.get("new_password")
    reset_token = request.form.get("reset_token")
    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"})
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

