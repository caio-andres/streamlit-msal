import streamlit as st

from src.page_login import get_authenticator, page_login


def main():
    st.set_page_config(page_title="Minha App", page_icon="🔐", layout="wide")

    # --- Autenticação ---
    # Retorna False e renderiza a tela de login se não estiver autenticado.
    if not page_login():
        st.stop()

    # --- Usuário autenticado ---
    auth = get_authenticator()
    user = auth.get_user()

    # Cabeçalho com info do usuário e botão de logout
    col1, col2 = st.columns([4, 1])
    with col1:
        st.title("Página Principal")
    with col2:
        if st.button("Sair", use_container_width=True):
            auth.logout()

    st.divider()

    # Informações do usuário logado
    st.subheader("Informações do usuário")
    col_a, col_b = st.columns(2)
    with col_a:
        st.metric("Nome", user.get("name", "—"))
        st.metric("E-mail", user.get("email", "—"))
    with col_b:
        st.metric("Object ID", user.get("oid", "—"))
        st.metric("Tenant ID", user.get("tid", "—"))

    st.divider()

    # Conteúdo da aplicação
    tela1, tela2 = st.tabs(["Tela 1", "Tela 2"])

    with tela1:
        st.write(f"Olá, **{user.get('name', 'usuário')}**! Bem-vindo à Tela 1.")

    with tela2:
        st.write("Conteúdo da Tela 2.")


if __name__ == "__main__":
    main()
