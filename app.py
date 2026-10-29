"""Consulta aos servidores da AGERGS – priorização de processos.

Serve o questionário (static/index.html), guarda uma resposta por navegador
no Postgres e oferece à coordenação um painel e a exportação em CSV
(protegidos por senha via HTTP Basic: usuário "coordenacao", senha em
ADMIN_PASSWORD).
"""
import csv
import hmac
import io
import json
import os
import re
import time
from collections import defaultdict, deque

import psycopg
from flask import Flask, Response, abort, jsonify, request, send_from_directory

app = Flask(__name__, static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 128 * 1024

DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

PROCESSOS = ["G1.1", "G1.2", "G2.1", "G2.2", "G2.3", "G3.1", "G3.2", "G4.1", "G4.2",
             "F1.1", "F2.1", "F2.2", "F2.3", "F2.4", "F2.5", "F3.1", "F3.2", "F3.3", "F3.4",
             "F3.5", "F3.6", "F4.1", "F4.2", "F5.1", "F5.2", "F5.3", "F5.4", "F5.5",
             "F6.1", "F6.2", "F6.3", "S1.1", "S1.2", "S2.1", "S2.2", "S3.1", "S4.1", "S5.1", "S6.1"]
RID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
MAX_PRIO = 5


def conn():
    return psycopg.connect(DATABASE_URL, autocommit=True)


with conn() as c:
    c.execute("""CREATE TABLE IF NOT EXISTS respostas (
                   id TEXT PRIMARY KEY,
                   dados JSONB NOT NULL,
                   criado TIMESTAMPTZ NOT NULL DEFAULT now(),
                   atualizado TIMESTAMPTZ NOT NULL DEFAULT now())""")

# limite simples por IP: 30 gravações a cada 10 minutos
_janela = defaultdict(deque)


def limite_ok(ip):
    agora, q = time.time(), _janela[ip]
    while q and agora - q[0] > 600:
        q.popleft()
    if len(q) >= 30:
        return False
    q.append(agora)
    return True


def texto(v, n):
    return v.strip()[:n] if isinstance(v, str) else ""


def limpa(d):
    """Mantém só os campos esperados, com tipos e tamanhos válidos."""
    r, prio = {}, 0
    for pid, x in (d.get("r") or {}).items():
        if pid not in PROCESSOS or not isinstance(x, dict):
            continue
        o = {}
        if x.get("f") in ("atuo", "conheco", "nao"):
            o["f"] = x["f"]
        if o.get("f") in ("atuo", "conheco"):
            for q in ("c2", "c3", "c4"):
                if isinstance(x.get(q), int) and 1 <= x[q] <= 5:
                    o[q] = x[q]
        if x.get("p") is True and prio < MAX_PRIO:
            o["p"], prio = True, prio + 1
        obs = texto(x.get("obs"), 1000)
        if obs:
            o["obs"] = obs
        if o:
            r[pid] = o
    return {"unidade": texto(d.get("unidade"), 120), "vinculo": texto(d.get("vinculo"), 120),
            "tempo": texto(d.get("tempo"), 60), "geral": texto(d.get("geral"), 3000), "r": r}


def exige_senha():
    a = request.authorization
    if not (a and a.username == "coordenacao" and hmac.compare_digest(a.password or "", ADMIN_PASSWORD)):
        return Response("Acesso restrito à coordenação.", 401,
                        {"WWW-Authenticate": 'Basic realm="Coordenacao AGERGS", charset="UTF-8"'})
    return None


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/healthz")
def healthz():
    return "ok"


@app.get("/api/resposta/<rid>")
def ler(rid):
    if not RID.match(rid):
        abort(400)
    with conn() as c:
        row = c.execute("SELECT dados FROM respostas WHERE id=%s", (rid,)).fetchone()
    if not row:
        abort(404)
    return jsonify({"dados": row[0]})


@app.put("/api/resposta/<rid>")
def gravar(rid):
    if not RID.match(rid):
        abort(400)
    ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()
    if not limite_ok(ip):
        abort(429)
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        abort(400)
    dados = limpa(d)
    with conn() as c:
        c.execute("""INSERT INTO respostas (id, dados) VALUES (%s, %s)
                     ON CONFLICT (id) DO UPDATE SET dados=EXCLUDED.dados, atualizado=now()""",
                  (rid, json.dumps(dados, ensure_ascii=False)))
    return jsonify({"ok": True})


def todas():
    with conn() as c:
        return c.execute("SELECT id, dados, atualizado FROM respostas ORDER BY criado").fetchall()


@app.get("/coordenacao")
def coordenacao():
    return exige_senha() or send_from_directory("static", "coordenacao.html")


@app.get("/api/admin/respostas")
def admin_respostas():
    neg = exige_senha()
    if neg:
        return neg
    return jsonify([{"dados": d, "atualizado": a.isoformat()} for _, d, a in todas()])


@app.get("/api/admin/csv")
def admin_csv():
    neg = exige_senha()
    if neg:
        return neg
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";", lineterminator="\n")
    w.writerow(["respondente", "unidade", "vinculo", "tempo", "processo", "relacao", "impacto_c2",
                "volume_c3", "problemas_c4", "prioridade", "comentario", "atualizado"])
    for i, (_, d, a) in enumerate(todas(), 1):
        rid, at = f"R{i:03d}", a.isoformat()
        base = [rid, d.get("unidade", ""), d.get("vinculo", ""), d.get("tempo", "")]
        for pid in PROCESSOS:
            x = (d.get("r") or {}).get(pid)
            if x:
                w.writerow(base + [pid, x.get("f", ""), x.get("c2", ""), x.get("c3", ""), x.get("c4", ""),
                                   1 if x.get("p") else 0, x.get("obs", ""), at])
        if d.get("geral"):
            w.writerow(base + ["GERAL", "", "", "", "", "", d["geral"], at])
    return Response("﻿" + buf.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=consulta_priorizacao_respostas.csv"})


@app.after_request
def cabecalhos(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith(("/api/admin", "/coordenacao")):
        resp.headers["Cache-Control"] = "no-store"
    return resp
