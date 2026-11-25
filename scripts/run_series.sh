#!/usr/bin/env bash
# Ablation series on the 200-domain input: each run adds one technique.
set -u
PY=./.venv/Scripts/python
IN=data/domains.parquet
mkdir -p logs
$PY -m techscan scan $IN --label "v1 naive: python UA, HTTP only, no retries" --ua naive --browser off --tiers http --retries 0 > logs/v1.log 2>&1
$PY -m techscan scan $IN --label "v2 real browser headers + URL variants + retries" --ua chrome --browser off --tiers http > logs/v2.log 2>&1
$PY -m techscan scan $IN --label "v3 + DNS, TLS, robots.txt" --ua chrome --browser off --tiers http,dns,tls,robots > logs/v3.log 2>&1
$PY -m techscan scan $IN --label "v4 + headless browser, smart escalation only" --browser smart --tiers http,browser,dns,tls,robots > logs/v4.log 2>&1
$PY -m techscan scan $IN --label "v5 headless browser on every live site + Wayback fallback" --browser all > logs/v5.log 2>&1
$PY -m techscan scan $IN --label "v6 + HTTP/1.1 fallback, bounded browser time, Wayback via CDX API" --browser all > logs/v6.log 2>&1
$PY -m techscan scan $IN --label "v7 DOM property rules evaluated in live DOM (fixes React/Preact false positives)" --browser all > logs/v7.log 2>&1
echo SERIES_DONE
