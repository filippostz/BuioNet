from flask import Flask
from flask_login import LoginManager
from datetime import datetime
from config import SECRET_KEY
from app.db import init_main_db
from app.auth import load_user, create_default_admin


def create_app():
    app = Flask(__name__)
    app.secret_key = SECRET_KEY

    @app.template_filter('format_ts')
    def format_ts(ts):
        try:
            return datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M')
        except Exception:
            return '—'

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def user_loader(user_id):
        return load_user(user_id)

    init_main_db()
    create_default_admin()

    from app.routes.auth import bp as auth_bp
    from app.routes.dashboard import bp as dash_bp
    from app.routes.workspace import bp as ws_bp
    from app.routes.scan import bp as scan_bp
    from app.routes.alerts import bp as alerts_bp
    from app.routes.users import bp as users_bp
    from app.routes.api import bp as api_bp
    from app.routes.assets import bp as assets_bp
    from app.routes.alert_rules import bp as alert_rules_bp
    from app.routes.api_keys import bp as api_keys_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dash_bp)
    app.register_blueprint(ws_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(alert_rules_bp)
    app.register_blueprint(api_keys_bp)

    return app
