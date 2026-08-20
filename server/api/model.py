from flask import Blueprint, jsonify

bp = Blueprint("model", __name__, url_prefix="/api/model")

@bp.route("/recalibrate", methods=["POST"])
def recalibrate():
    """
    The current G-model is a static, pre-trained InferenceEngine.
    Retraining on the server is disabled to preserve the model exactly as provided.
    """
    return jsonify({
        "ok": False, 
        "error": "The G-model is static and pre-trained. On-server retraining is disabled."
    }), 400
