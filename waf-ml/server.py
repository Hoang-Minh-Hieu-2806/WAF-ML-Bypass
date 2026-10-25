"""T03 — entrypoint của waf-ml container: bảo đảm model + chạy uvicorn.

Nếu $ML_MODEL_DIR/chưa có model.joblib -> train nhanh trước, rồi set env
ML_MODEL_VERSION để app.py dùng đúng phiên bản sinh ra. Đảm bảo image luôn
khớp sklearn version pin trong requirements (host train bằng 1.9 cũng có thể
khác, container tự train lại để pickle liền mạch).
"""
import os

import uvicorn


def main():
    port = int(os.getenv("PORT", "5001"))
    from train import ensure_model

    version = ensure_model()
    os.environ["ML_MODEL_VERSION"] = version
    print(f"[waf-ml] model ready: {version}", flush=True)
    uvicorn.run("app:app", host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
