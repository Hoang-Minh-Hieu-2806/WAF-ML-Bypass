"""T03 — entrypoint của waf-ml container: bảo đảm model + chạy uvicorn.

Nạp artifact đã chọn và set ML_MODEL_VERSION cho app.py. Chỉ train khi
ML_FORCE_TRAIN=1 được đặt rõ ràng; tránh thay đổi model mốc khi artifact thiếu.
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
