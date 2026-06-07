from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from datetime import datetime, timedelta
from typing import Any
import psycopg2
import psycopg2.extras
import json
import os


class Settings(BaseSettings):
    database_url: str
    secret_key: str = "troque-essa-chave-em-producao"
    usuario_email: str
    usuario_senha: str
    algorithm: str = "HS256"
    token_expire_minutes: int = 60 * 24 * 30  # 30 dias

    class Config:
        env_file = ".env"


settings = Settings()

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="PoupaPrin API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Banco ────────────────────────────────────────────────────────────────────

def get_conn():
    return psycopg2.connect(settings.database_url, cursor_factory=psycopg2.extras.RealDictCursor)


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS dados (
                    id SERIAL PRIMARY KEY,
                    payload JSONB NOT NULL,
                    atualizado_em TIMESTAMPTZ DEFAULT NOW()
                )
            """)
        conn.commit()


@app.on_event("startup")
def startup():
    init_db()


# ─── Auth ─────────────────────────────────────────────────────────────────────

def criar_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.token_expire_minutes)
    return jwt.encode({"sub": email, "exp": expire}, settings.secret_key, algorithm=settings.algorithm)


def verificar_token(token: str = Depends(oauth2)) -> str:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        email = payload.get("sub")
        if email != settings.usuario_email:
            raise HTTPException(status_code=401, detail="Não autorizado")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@app.post("/auth/login", response_model=TokenResponse)
def login(form: OAuth2PasswordRequestForm = Depends()):
    if form.username != settings.usuario_email:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    if not pwd_ctx.verify(form.password, pwd_ctx.hash(settings.usuario_senha)):
        # Comparação direta para usuário único
        if form.password != settings.usuario_senha:
            raise HTTPException(status_code=401, detail="Credenciais inválidas")
    return TokenResponse(access_token=criar_token(form.username))


# ─── Dados ────────────────────────────────────────────────────────────────────

class DadosPayload(BaseModel):
    payload: Any


@app.get("/dados")
def get_dados(email: str = Depends(verificar_token)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT payload FROM dados ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
    if not row:
        return {"payload": None}
    return {"payload": row["payload"]}


@app.put("/dados")
def save_dados(body: DadosPayload, email: str = Depends(verificar_token)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM dados LIMIT 1")
            existe = cur.fetchone()
            if existe:
                cur.execute(
                    "UPDATE dados SET payload = %s, atualizado_em = NOW() WHERE id = %s",
                    (json.dumps(body.payload), existe["id"])
                )
            else:
                cur.execute(
                    "INSERT INTO dados (payload) VALUES (%s)",
                    (json.dumps(body.payload),)
                )
        conn.commit()
    return {"ok": True}


@app.get("/health")
def health():
    return {"status": "ok"}
