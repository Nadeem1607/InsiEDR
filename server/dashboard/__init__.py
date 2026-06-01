from __future__ import annotations

from flask import Blueprint, render_template

bp = Blueprint("dashboard", __name__, template_folder="templates", url_prefix="/dashboard")


@bp.route("/", methods=["GET"])
def index():
    return render_template("dashboard.html")
