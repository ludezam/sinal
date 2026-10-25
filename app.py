import re
from urllib.parse import urlparse
import streamlit as st

# Configuração da Página
st.set_page_config(
    page_title="Verificador de Segurança de URLs",
    page_icon="🛡️",
    layout="centered"
)

def analisar_url(url_alvo):
    if not url_alvo.startswith("http://") and not url_alvo.startswith("https://"):
        url_alvo = "https://" + url_alvo

    parsed = urlparse(url_alvo)
    dominio = parsed.netloc
    caminho = parsed.path
    
    pontos_risco = 0
    alertas = []

    # 1. Verificar HTTPS
    if parsed.scheme == "http":
        pontos_risco += 3
        alertas.append("Uso de HTTP inseguro (sem encriptação SSL).")

    # 2. Endereço IP direto
    padrao_ip = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if padrao_ip.match(dominio):
        pontos_risco += 5
        alertas.append("O domínio é um endereço IP direto em vez de um nome de domínio legítimo.")

    # 3. Comprimento excessivo
    if len(url_alvo) > 75:
        pontos_risco += 1
        alertas.append("A URL é demasiado longa, o que pode indicar tentativa de ocultar o destino real.")

    # 4. Termos suspeitos
    termos_suspeitos = ['login', 'signin', 'verificar', 'conta', 'update', 'banking', 'seguro', 'suporte', 'acessar']
    if any(termo in url_alvo.lower() for termo in termos_suspeitos):
        pontos_risco += 2
        alertas.append("Contém palavras-chave frequentemente associadas a páginas de login ou roubo de credenciais.")

    # 5. Excesso de hífens ou subdomínios
    if dominio.count('-') > 2 or dominio.count('.') > 3:
        pontos_risco += 2
        alertas.append("Estrutura excessiva de subdomínios ou hífens (possível imitação de marca/phishing).")

    return dominio, pontos_risco, alertas

# --- Interface Gráfica com Streamlit ---
st.title("🛡️ Verificador de Segurança de URLs")
st.markdown("Insira abaixo o endereço de um site para analisar indícios de risco, fraudes ou *phishing* com base em heurísticas de segurança.")

url_usuario = st.text_input("Digite ou cole a URL aqui:", placeholder="https://exemplo.com")

if st.button("Analisar Site", type="primary"):
    if url_usuario:
        with st.spinner("A analisar a estrutura do link..."):
            dominio, risco, lista_alertas = analisar_url(url_usuario)
            
            st.markdown("---")
            st.subheader("📊 Relatório de Análise")
            st.write(f"**Domínio detetado:** `{dominio}`")
            
            # Exibição baseada no risco
            if risco == 0:
                st.success("Estado: **SEGURO** (Nenhum indicador óbvio de risco detetado).")
            elif risco <= 3:
                st.warning("Estado: **ATENÇÃO** (Risco baixo, navegue com cautela).")
            else:
                st.error("Estado: **PERIGO POTENCIAL** (Vários indicadores de risco/phishing detetados).")
                
            st.metric(label="Pontuação de Risco", value=f"{risco} / 13")
            
            if lista_alertas:
                st.markdown("### ⚠️ Alertas Encontrados:")
                for alerta in lista_alertas:
                    st.markdown(f"- {alerta}")
            else:
                st.info("Nenhum alerta de segurança relevante na estrutura da URL.")
    else:
        st.warning("Por favor, insira uma URL válida antes de clicar em analisar.")
