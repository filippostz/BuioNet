from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
from app.auth import get_user_by_username, verify_password, User

bp = Blueprint('auth', __name__)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        row = get_user_by_username(username)
        if row and verify_password(row['password_hash'], password) and row['active']:
            user = User(row['id'], row['username'], row['role'], row['active'])
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
