# T03 — waf-crs image (deployment thuộc Hiếu, rule thuộc Huy).
# Base official OWASP CRS v4 trên Nginx + ModSecurity v3.
# Phase 1: DetectionOnly để benign qua 200. Huy bật blocking + audit log ở Tuần 03-04.
# NOTE: tag rolling `nginx` = dòng CRS v4 stable mới nhất; Huy sẽ pin stable tag
# `<CRS>-nginx-<date>` (vd 4.25.x LTS) ở Tuần 03-04 để tái lập.
FROM owasp/modsecurity-crs:nginx

# curl cho healthcheck của compose (image gốc không sẵn).
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*
USER nginx

ENV PARANOIA=1 \
    MODSEC_RULE_ENGINE=DetectionOnly \
    BACKEND=http://web-app:5000 \
    ANOMALY_INBOUND=5 \
    ALLOWED_METHODS="GET HEAD POST OPTIONS"

EXPOSE 8080
