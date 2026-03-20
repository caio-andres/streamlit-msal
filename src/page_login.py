"""
Página de login — delegada ao MSALAuthenticator.
Mantido aqui para compatibilidade com a importação em main.py.
"""

import streamlit as st
from src.auth.msal_auth import MSALAuthenticator

# Configuração centralizada — edite apenas aqui
CLIENT_ID = "0f138edb-f803-4c11-a561-be1aca213ca0"
TENANT_ID = "d0c4dae0-c81a-4cd8-8cf5-3d3c1565c99b"
REDIRECT_URI = "http://localhost:8501/"

# client_secret é obrigatório para apps WEB (Confidential Client).
# Adicione seu secret aqui ou carregue de variável de ambiente:
#   import os; CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")
CLIENT_SECRET = None  # substitua pelo seu secret


def get_authenticator() -> MSALAuthenticator:
    """Retorna (ou cria) o autenticador armazenado no session_state."""
    if "msal_authenticator" not in st.session_state:
        st.session_state["msal_authenticator"] = MSALAuthenticator(
            client_id=CLIENT_ID,
            tenant_id=TENANT_ID,
            redirect_uri=REDIRECT_URI,
            client_secret=CLIENT_SECRET,
        )
    return st.session_state["msal_authenticator"]


def page_login() -> bool:
    """
    Gerencia autenticação.

    Retorna True se o usuário está autenticado.
    Chame st.stop() quando retornar False para impedir que
    o restante da página seja renderizado.
    """
    auth = get_authenticator()

    # Detecta se estamos rodando dentro do popup de callback
    if "code" in st.query_params:
        # Estamos no popup — trocar o code e enviar postMessage ao parent
        auth.render_popup_callback()
        return False  # st.stop() já foi chamado dentro de render_popup_callback

    return auth.authenticate()
