"""
MSALAuthenticator
-----------------
Classe responsável por toda a autenticação MSAL (Authorization Code Flow + PKCE)
dentro de uma aplicação Streamlit.

Fluxo popup:
  1. Janela principal gera auth URL → armazena auth_flow no cache de módulo
  2. JS abre popup com a URL da Microsoft
  3. Microsoft redireciona popup → localhost:8501/?code=XXX&state=YYY
  4. Streamlit do popup lê o flow pelo state, troca code por token
  5. Popup envia postMessage ao parent e fecha
  6. Janela principal recebe mensagem → navega para /?auth_done=YYY
  7. Streamlit lê token do cache, popula session_state, renderiza app
"""

import time
import msal
import streamlit as st
import streamlit.components.v1 as components

# ---------------------------------------------------------------------------
# Cache em nível de módulo — compartilhado entre TODAS as sessões Streamlit
# do mesmo processo (parent + popup são sessões distintas, mas mesmo processo)
# ---------------------------------------------------------------------------
_auth_flow_cache: dict[str, dict] = {}  # state  → msal auth_flow dict
_token_cache: dict[str, dict] = {}  # state  → {user, access_token, expires_at}
_CACHE_TTL = 600  # segundos (10 min)


def _cleanup_expired() -> None:
    """Remove entradas expiradas dos caches."""
    now = time.time()
    for key in list(_auth_flow_cache.keys()):
        if _auth_flow_cache[key].get("_created_at", 0) + _CACHE_TTL < now:
            del _auth_flow_cache[key]
    for key in list(_token_cache.keys()):
        if _token_cache[key].get("expires_at", 0) < now:
            del _token_cache[key]


class MSALAuthenticator:
    """
    Gerencia autenticação MSAL via Authorization Code Flow com popup.

    Parâmetros
    ----------
    client_id : str
        Application (client) ID registrado no Azure AD.
    tenant_id : str
        Directory (tenant) ID do Azure AD.
    redirect_uri : str
        URI de redirecionamento registrado no Azure AD.
        Para dev local: "http://localhost:8501/"
    client_secret : str | None
        Client secret para Confidential Client (aplicações web).
        Se None, usa Public Client com PKCE (menos seguro para web).
    scopes : list[str] | None
        Escopos do Microsoft Graph desejados.
        Padrão: ["User.Read", "openid", "profile", "email"]
    """

    def __init__(
        self,
        client_id: str,
        tenant_id: str,
        redirect_uri: str,
        client_secret: str | None = None,
        scopes: list[str] | None = None,
    ) -> None:
        self.client_id = client_id
        self.tenant_id = tenant_id
        self.redirect_uri = redirect_uri
        self.client_secret = client_secret
        self.scopes = scopes or ["User.Read", "email"]
        self.authority = f"https://login.microsoftonline.com/{tenant_id}"

        if client_secret:
            self._msal_app = msal.ConfidentialClientApplication(
                client_id=client_id,
                client_credential=client_secret,
                authority=self.authority,
            )
        else:
            self._msal_app = msal.PublicClientApplication(
                client_id=client_id,
                authority=self.authority,
            )

    # ------------------------------------------------------------------
    # Propriedades públicas
    # ------------------------------------------------------------------

    def is_authenticated(self) -> bool:
        """Retorna True se o usuário já está autenticado nesta sessão."""
        return bool(st.session_state.get("msal_user"))

    def get_user(self) -> dict | None:
        """Retorna dados do usuário autenticado ou None."""
        return st.session_state.get("msal_user")

    def get_access_token(self) -> str | None:
        """Retorna o access token ou None."""
        return st.session_state.get("msal_access_token")

    def logout(self) -> None:
        """Limpa a sessão e redireciona para a página inicial."""
        for key in ("msal_user", "msal_access_token"):
            st.session_state.pop(key, None)
        st.query_params.clear()
        st.rerun()

    # ------------------------------------------------------------------
    # Método principal — chamar no topo do app
    # ------------------------------------------------------------------

    def authenticate(self) -> bool:
        """
        Ponto de entrada principal. Chame no topo do seu app Streamlit.

        Retorna True se o usuário está (ou acabou de ficar) autenticado.
        Quando retorna False, já renderizou a página de login — basta parar.

        Exemplo de uso
        --------------
        auth = MSALAuthenticator(...)
        if not auth.authenticate():
            st.stop()
        # código da página principal aqui
        """
        _cleanup_expired()

        # 1. Já autenticado nesta sessão → ok
        if self.is_authenticated():
            return True

        params = st.query_params

        # 2. Retorno do popup: janela principal recebeu auth_done=<state>
        if "auth_done" in params:
            state = params["auth_done"]
            entry = _token_cache.get(state)
            if entry and entry.get("expires_at", 0) > time.time():
                st.session_state["msal_user"] = entry["user"]
                st.session_state["msal_access_token"] = entry["access_token"]
                del _token_cache[state]
                st.query_params.clear()
                st.rerun()
            else:
                st.query_params.clear()
                st.error("Sessão expirada ou inválida. Tente novamente.")
            return False

        # 3. Callback OAuth direto na janela (popup ou redirect sem window.opener)
        if "code" in params:
            self._handle_direct_callback(params)
            return False

        # 4. Não autenticado → renderiza página de login
        self._render_login_page()
        return False

    # ------------------------------------------------------------------
    # Lógica interna
    # ------------------------------------------------------------------

    def _get_auth_url(self) -> str:
        """Gera a URL de autorização e salva o flow no cache de módulo."""
        flow = self._msal_app.initiate_auth_code_flow(
            scopes=self.scopes,
            redirect_uri=self.redirect_uri,
        )
        flow["_created_at"] = time.time()
        state = flow.get("state", "")
        _auth_flow_cache[state] = flow
        return flow["auth_uri"]

    def _handle_direct_callback(self, params) -> None:
        """
        Trata o callback OAuth quando a janela atual (popup ou main)
        recebe ?code=XXX&state=YYY.

        Se estivermos no popup (window.opener != null), o JS envia
        postMessage ao parent e fecha. Caso contrário (redirect direto),
        troca o code pelo token aqui mesmo.
        """
        code = params.get("code", "")
        state = params.get("state", "")
        session_state_param = params.get("session_state", "")
        error = params.get("error", "")

        if error:
            st.query_params.clear()
            st.error(f"Erro de autenticação: {params.get('error_description', error)}")
            return

        # Renderiza HTML mínimo com JS:
        # - se popup: postMessage → parent e fecha
        # - se janela principal: troca o code direto
        popup_bridge_html = f"""
        <!DOCTYPE html>
        <html>
        <body style="background:#f0f2f6;display:flex;align-items:center;
                     justify-content:center;height:100vh;margin:0;
                     font-family:sans-serif;color:#444;">
          <p>Autenticando, aguarde...</p>
          <script>
            (function() {{
              if (window.opener !== null && !window.opener.closed) {{
                window.opener.postMessage(
                  {{
                    type: "MSAL_AUTH_SUCCESS",
                    code: {code!r},
                    state: {state!r},
                    session_state: {session_state_param!r}
                  }},
                  window.location.origin
                );
                window.close();
              }} else {{
                // Não é popup — redireciona com flag para troca direta
                const url = new URL(window.location.href);
                url.searchParams.set("direct_exchange", "1");
                window.location.href = url.toString();
              }}
            }})();
          </script>
        </body>
        </html>
        """
        components.html(popup_bridge_html, height=80)

        # Se chegou aqui com direct_exchange, trocamos o code pelo token
        if params.get("direct_exchange") == "1":
            self._exchange_code_and_store_session(code, state, session_state_param)

    def _exchange_code_and_store_session(
        self, code: str, state: str, session_state_param: str
    ) -> None:
        """Troca o auth code pelo token e popula o session_state."""
        flow = _auth_flow_cache.get(state)
        if not flow:
            st.query_params.clear()
            st.error("Flow de autenticação expirado. Tente fazer login novamente.")
            return

        auth_response = {
            "code": code,
            "state": state,
            "session_state": session_state_param,
        }

        result = self._msal_app.acquire_token_by_auth_code_flow(
            auth_code_flow=flow,
            auth_response=auth_response,
        )

        _auth_flow_cache.pop(state, None)

        if "error" in result:
            st.query_params.clear()
            st.error(
                f"Falha na autenticação: {result.get('error_description', result['error'])}"
            )
            return

        claims = result.get("id_token_claims", {})
        user = {
            "name": claims.get("name", ""),
            "email": claims.get("preferred_username", ""),
            "oid": claims.get("oid", ""),
            "tid": claims.get("tid", ""),
        }

        st.session_state["msal_user"] = user
        st.session_state["msal_access_token"] = result.get("access_token")
        st.query_params.clear()
        st.rerun()

    def exchange_code_for_popup(
        self, code: str, state: str, session_state_param: str
    ) -> bool:
        """
        Chamado quando o Streamlit roda dentro do popup e precisa trocar
        o code pelo token para depois avisar o parent via cache.

        Retorna True em caso de sucesso.
        """
        flow = _auth_flow_cache.get(state)
        if not flow:
            return False

        auth_response = {
            "code": code,
            "state": state,
            "session_state": session_state_param,
        }

        result = self._msal_app.acquire_token_by_auth_code_flow(
            auth_code_flow=flow,
            auth_response=auth_response,
        )

        _auth_flow_cache.pop(state, None)

        if "error" in result:
            return False

        claims = result.get("id_token_claims", {})
        user = {
            "name": claims.get("name", ""),
            "email": claims.get("preferred_username", ""),
            "oid": claims.get("oid", ""),
            "tid": claims.get("tid", ""),
        }

        _token_cache[state] = {
            "user": user,
            "access_token": result.get("access_token"),
            "expires_at": time.time() + _CACHE_TTL,
        }
        return True

    # ------------------------------------------------------------------
    # Renderização
    # ------------------------------------------------------------------

    def _render_login_page(self) -> None:
        """Renderiza a página de login com botão que abre popup."""
        auth_url = self._get_auth_url()

        login_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8"/>
          <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{
              background: #f0f2f6;
              display: flex;
              align-items: center;
              justify-content: center;
              min-height: 100vh;
              font-family: -apple-system, BlinkMac'SystemFont, "Segoe UI", sans-serif;
            }}
            .card {{
              background: white;
              border-radius: 12px;
              box-shadow: 0 4px 24px rgba(0,0,0,0.10);
              padding: 48px 40px;
              width: 360px;
              text-align: center;
            }}
            .logo {{ width: 56px; margin-bottom: 24px; }}
            h2 {{ color: #1f1f1f; font-size: 22px; margin-bottom: 8px; }}
            p  {{ color: #666; font-size: 14px; margin-bottom: 32px; line-height: 1.5; }}
            .btn {{
              display: flex;
              align-items: center;
              justify-content: center;
              gap: 10px;
              width: 100%;
              padding: 12px 20px;
              background: #0078d4;
              color: white;
              border: none;
              border-radius: 4px;
              font-size: 15px;
              cursor: pointer;
              transition: background 0.2s;
            }}
            .btn:hover {{ background: #106ebe; }}
            .btn:active {{ background: #005a9e; }}
            .btn svg {{ flex-shrink: 0; }}
            #status {{
              margin-top: 18px;
              font-size: 13px;
              color: #888;
              min-height: 20px;
            }}
            .spinner {{
              display: inline-block;
              width: 14px; height: 14px;
              border: 2px solid #ccc;
              border-top-color: #0078d4;
              border-radius: 50%;
              animation: spin 0.8s linear infinite;
              vertical-align: middle;
              margin-right: 6px;
            }}
            @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
          </style>
        </head>
        <body>
          <div class="card">
            <!-- Microsoft logo SVG -->
            <svg class="logo" viewBox="0 0 23 23" xmlns="http://www.w3.org/2000/svg">
              <rect x="1"  y="1"  width="10" height="10" fill="#f25022"/>
              <rect x="12" y="1"  width="10" height="10" fill="#7fba00"/>
              <rect x="1"  y="12" width="10" height="10" fill="#00a4ef"/>
              <rect x="12" y="12" width="10" height="10" fill="#ffb900"/>
            </svg>
            <h2>Bem-vindo</h2>
            <p>Faça login com sua conta Microsoft<br/>para continuar.</p>
            <button class="btn" id="loginBtn" onclick="openLoginPopup()">
              <svg width="20" height="20" viewBox="0 0 23 23" xmlns="http://www.w3.org/2000/svg">
                <rect x="1"  y="1"  width="10" height="10" fill="#f25022"/>
                <rect x="12" y="1"  width="10" height="10" fill="#7fba00"/>
                <rect x="1"  y="12" width="10" height="10" fill="#00a4ef"/>
                <rect x="12" y="12" width="10" height="10" fill="#ffb900"/>
              </svg>
              Entrar com Microsoft
            </button>
            <div id="status"></div>
          </div>

          <script>
            const AUTH_URL = {auth_url!r};

            function openLoginPopup() {{
              const w = 520, h = 640;
              const left = Math.max(0, (screen.width  - w) / 2);
              const top  = Math.max(0, (screen.height - h) / 2);
              const features = [
                "width="  + w,
                "height=" + h,
                "left="   + left,
                "top="    + top,
                "scrollbars=yes",
                "resizable=yes",
                "toolbar=no",
                "menubar=no",
                "location=no",
              ].join(",");

              const popup = window.open(AUTH_URL, "msalLoginPopup", features);

              if (!popup || popup.closed || typeof popup.closed === "undefined") {{
                setStatus("❌ Popup bloqueado. Libere popups para este site e tente novamente.", true);
                return;
              }}

              setStatus('<span class="spinner"></span>Aguardando autenticação...');
              document.getElementById("loginBtn").disabled = true;

              // Ouve postMessage do popup
              window.addEventListener("message", function onMsg(event) {{
                if (event.origin !== window.location.origin) return;
                const data = event.data;

                if (data && data.type === "MSAL_AUTH_SUCCESS") {{
                  window.removeEventListener("message", onMsg);
                  setStatus('<span class="spinner"></span>Autenticado! Redirecionando...');

                  // Redireciona a janela principal para processar o token
                  const url = new URL(window.location.href);
                  url.searchParams.set("auth_done", data.state);
                  // Limpa params de callback que não queremos
                  url.searchParams.delete("code");
                  url.searchParams.delete("session_state");
                  window.location.href = url.toString();
                }}

                if (data && data.type === "MSAL_AUTH_ERROR") {{
                  window.removeEventListener("message", onMsg);
                  setStatus("❌ Erro no login: " + (data.error_description || data.error), true);
                  document.getElementById("loginBtn").disabled = false;
                }}
              }}, false);

              // Detecta popup fechado manualmente
              const poll = setInterval(function() {{
                if (popup.closed) {{
                  clearInterval(poll);
                  const status = document.getElementById("status").innerText;
                  if (status.includes("Aguardando")) {{
                    setStatus("Login cancelado.");
                    document.getElementById("loginBtn").disabled = false;
                  }}
                }}
              }}, 600);
            }}

            function setStatus(html, isError) {{
              const el = document.getElementById("status");
              el.innerHTML = html;
              el.style.color = isError ? "#c00" : "#888";
            }}
          </script>
        </body>
        </html>
        """
        # height=0 esconde o iframe — a página de login vem do HTML acima
        # mas precisamos de uma altura maior para o card aparecer
        components.html(login_html, height=520, scrolling=False)

    def render_popup_callback(self) -> None:
        """
        Renderiza a página de callback dentro do popup.

        Troca o code pelo token via cache compartilhado e envia
        postMessage ao parent antes de fechar o popup.

        Chame este método quando detectar que o Streamlit está rodando
        dentro do popup com ?code=XXX nos query params.
        """
        params = st.query_params
        code = params.get("code", "")
        state = params.get("state", "")
        session_state_param = params.get("session_state", "")
        error = params.get("error", "")

        if error:
            error_html = f"""
            <script>
              if (window.opener && !window.opener.closed) {{
                window.opener.postMessage(
                  {{ type: "MSAL_AUTH_ERROR",
                    error: {error!r},
                    error_description: {params.get("error_description", "")!r} }},
                  window.location.origin
                );
              }}
              window.close();
            </script>
            """
            components.html(error_html, height=0)
            st.stop()
            return

        # Troca code → token e guarda no cache compartilhado
        success = self.exchange_code_for_popup(code, state, session_state_param)

        msg_type = "MSAL_AUTH_SUCCESS" if success else "MSAL_AUTH_ERROR"
        extra = f"state: {state!r}" if success else 'error: "token_exchange_failed"'

        callback_html = f"""
        <!DOCTYPE html>
        <html>
        <body style="background:#f0f2f6;display:flex;align-items:center;
                     justify-content:center;height:100vh;margin:0;
                     font-family:sans-serif;color:#444;font-size:15px;">
          <p>Autenticado! Fechando janela...</p>
          <script>
            (function() {{
              if (window.opener && !window.opener.closed) {{
                window.opener.postMessage(
                  {{ type: {msg_type!r}, {extra} }},
                  window.location.origin
                );
                window.close();
              }} else {{
                // Fallback: redireciona a própria janela
                const url = new URL(window.location.origin + window.location.pathname);
                url.searchParams.set("auth_done", {state!r});
                window.location.href = url.toString();
              }}
            }})();
          </script>
        </body>
        </html>
        """
        components.html(callback_html, height=80)
        st.stop()
