# -*- coding: utf-8 -*-
"""
app.py
======
Interfaz web (Streamlit) para el proyecto "Cifrado y Descifrado César / Atbash".

Cómo ejecutarlo localmente:
    pip install -r requirements.txt
    streamlit run app.py

Cómo publicarlo gratis en la web:
    Ver el archivo README.md (opción recomendada: Streamlit Community Cloud).
"""

import streamlit as st
from crypto_engine import (
    Alfabeto,
    cifrar_cesar,
    cifrar_atbash,
    auto_descifrar,
)

st.set_page_config(
    page_title="Cifrado César / Atbash",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# ESTILOS
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
        .block-container { padding-top: 2rem; max-width: 1000px; }
        .resultado-box {
            background-color: rgba(46, 204, 113, 0.08);
            border: 1px solid rgba(46, 204, 113, 0.4);
            border-radius: 10px;
            padding: 1.2rem 1.4rem;
            margin-top: 0.8rem;
        }
        .metodo-badge {
            display: inline-block;
            background-color: #2e86de;
            color: white;
            padding: 3px 12px;
            border-radius: 999px;
            font-size: 0.85rem;
            font-weight: 600;
            margin-left: 6px;
        }
        h1, h2, h3 { font-weight: 700; }
        .stTabs [data-baseweb="tab"] { font-size: 1.05rem; padding: 0.4rem 1.1rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# ENCABEZADO
# ---------------------------------------------------------------------------
st.title("🔐 Cifrado y Descifrado: César / Atbash")
st.markdown(
    "Proyecto académico de criptografía clásica &nbsp;·&nbsp; "
    "el descifrado automático usa análisis de frecuencias "
    "(criptoanálisis inspirado en **Al-Kindi**, siglo IX)."
)
st.divider()

# ---------------------------------------------------------------------------
# BARRA LATERAL: PASO 1 — Definir el alfabeto (conjunto de caracteres)
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Configuración del alfabeto")
    st.caption("Este conjunto de caracteres se usará como base para cifrar y descifrar.")

    modo_alfabeto = st.radio(
        "¿Cómo quieres definir el alfabeto?",
        [
            "Solo letras + espacio (recomendado)",
            "Imprimibles ASCII completos (32-126)",
            "Rango ASCII personalizado",
            "Escribir mi propio conjunto de símbolos",
        ],
    )

    if modo_alfabeto == "Solo letras + espacio (recomendado)":
        alfabeto = Alfabeto.desde_cadena("abcdefghijklmnopqrstuvwxyzñ ")

    elif modo_alfabeto == "Imprimibles ASCII completos (32-126)":
        alfabeto = Alfabeto.ascii_imprimible()

    elif modo_alfabeto == "Rango ASCII personalizado":
        codigo_inicio = st.number_input("Código inicial", min_value=0, max_value=1114111, value=32)
        codigo_fin = st.number_input("Código final", min_value=0, max_value=1114111, value=126)
        try:
            alfabeto = Alfabeto.generar_desde_ascii(int(codigo_inicio), int(codigo_fin))
        except ValueError as e:
            st.error(str(e))
            st.stop()

    else:  # Conjunto personalizado, puede incluir símbolos fuera del ASCII estándar
        cadena_simbolos = st.text_input(
            "Caracteres del alfabeto (sin repetir):",
            value="abcdefghijklmnopqrstuvwxyzñ",
        )
        if not cadena_simbolos:
            st.warning("Escribe al menos 2 caracteres.")
            st.stop()
        try:
            alfabeto = Alfabeto.desde_cadena(cadena_simbolos)
        except ValueError as e:
            st.error(str(e))
            st.stop()

    st.metric("Tamaño del alfabeto", len(alfabeto))
    with st.expander("Ver caracteres"):
        st.code("".join(alfabeto.caracteres))

    if modo_alfabeto == "Imprimibles ASCII completos (32-126)":
        st.info(
            "💡 Mezclar mayúsculas, minúsculas, números y símbolos en un mismo "
            "alfabeto es válido, pero puede generar ambigüedades en la "
            "detección automática con mensajes muy cortos (una sola palabra). "
            "Para la demo, la opción 'Solo letras + espacio' es más estable.",
            icon="💡",
        )

    st.divider()
    with st.expander("ℹ️ Fundamento teórico"):
        st.markdown(
            """
            El descifrado automático se basa en el **análisis de frecuencias**,
            técnica documentada por primera vez por **Abu Yusuf Ya'qub ibn
            Ishaq al-Kindi** (s. IX) en su tratado sobre el desciframiento de
            mensajes criptográficos. En cualquier idioma, ciertas letras se
            repiten con una frecuencia estadísticamente predecible, y esa
            "huella digital" sobrevive a una sustitución simple como César o
            Atbash. Comparando la distribución de frecuencias de cada posible
            descifrado contra la del español real (chi-cuadrado), más una
            verificación con palabras comunes del idioma, el sistema decide
            matemáticamente cuál es la única hipótesis correcta — sin que un
            humano indique el método o la clave.
            """
        )

# ---------------------------------------------------------------------------
# CUERPO PRINCIPAL: Tabs para Cifrar / Descifrar
# ---------------------------------------------------------------------------
tab_cifrar, tab_descifrar = st.tabs(["🔒  Cifrar mensaje", "🔓  Descifrar mensaje"])

# --- CIFRAR — aquí SÍ el usuario elige el módulo (requisito de la rúbrica) ---
with tab_cifrar:
    st.subheader("Cifrar un mensaje")

    col_izq, col_der = st.columns([2, 1])
    with col_izq:
        texto_plano = st.text_area("Mensaje a cifrar:", height=120, key="texto_plano")
    with col_der:
        metodo = st.selectbox("Módulo de cifrado:", ["César", "Atbash"])
        desplazamiento = 0
        if metodo == "César":
            desplazamiento = st.number_input(
                "Desplazamiento (clave):",
                min_value=1, max_value=max(1, len(alfabeto) - 1), value=3,
            )

    if st.button("🔒 Cifrar mensaje", type="primary", use_container_width=True):
        if not texto_plano:
            st.warning("Escribe un mensaje primero.")
        else:
            faltantes = sorted({c for c in texto_plano if not alfabeto.contiene(c)})
            if faltantes:
                st.info(f"Caracteres fuera del alfabeto (se dejan sin cifrar): {faltantes}")

            if metodo == "César":
                resultado = cifrar_cesar(texto_plano, alfabeto, int(desplazamiento))
            else:
                resultado = cifrar_atbash(texto_plano, alfabeto)

            st.markdown(
                f"""
                <div class="resultado-box">
                    <b>Mensaje cifrado</b><span class="metodo-badge">{metodo}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.code(resultado, language=None)

# --- DESCIFRAR — 100% automático, sin que el humano indique el módulo/clave ---
with tab_descifrar:
    st.subheader("Descifrar un mensaje")
    st.caption(
        "El sistema detecta automáticamente si se usó César (y con qué "
        "desplazamiento) o Atbash. No necesitas indicarlo."
    )

    texto_cifrado = st.text_area("Mensaje cifrado:", height=120, key="texto_cifrado")

    if st.button("🔓 Descifrar automáticamente", type="primary", use_container_width=True):
        if not texto_cifrado:
            st.warning("Pega un mensaje cifrado primero.")
        else:
            resultado = auto_descifrar(texto_cifrado, alfabeto)

            metodo_txt = (
                f"César (desplazamiento {resultado.parametro})"
                if resultado.metodo_detectado == "CESAR"
                else "Atbash"
            )

            if resultado.confianza == "ALTA":
                st.markdown(
                    f"""
                    <div class="resultado-box">
                        <b>✅ Mensaje descifrado</b><span class="metodo-badge">{metodo_txt}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.code(resultado.texto_descifrado, language=None)
            else:
                st.warning(
                    "⚠️ El sistema no encontró ninguna palabra real reconocible en "
                    "ningún posible descifrado. Esto ocurre cuando el mensaje original "
                    "no tiene estructura de lenguaje natural (símbolos al azar, patrones "
                    "repetitivos, contraseñas sin palabras reales, etc.). En ese caso, "
                    "el análisis de frecuencias NO tiene información suficiente para "
                    "determinar con certeza cuál desplazamiento es el correcto — esto es "
                    "un límite matemático del criptoanálisis clásico, no un error del "
                    "sistema. Aquí está la mejor hipótesis, junto con otras igual de "
                    "plausibles:"
                )
                st.markdown(
                    f"""
                    <div class="resultado-box">
                        <b>Mejor hipótesis</b><span class="metodo-badge">{metodo_txt}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.code(resultado.texto_descifrado, language=None)

                if resultado.alternativas:
                    with st.expander("Ver otras hipótesis igual de plausibles"):
                        for texto_alt, metodo_alt, param_alt in resultado.alternativas:
                            etiqueta = (
                                f"César (k={param_alt})" if metodo_alt == "CESAR" else "Atbash"
                            )
                            st.code(f"[{etiqueta}]  {texto_alt}", language=None)

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Confianza", resultado.confianza)
            c2.metric("Palabras reconocidas", f"{resultado.palabras_reconocidas:g}")
            c3.metric("Cobertura alfabética", f"{resultado.cobertura:.0%}")
            c4.metric("Chi-cuadrado", f"{resultado.puntaje_chi_cuadrado:.2f}")
            st.caption(
                "El sistema combina estas señales para decidir automáticamente, sin "
                "intervención humana, cuál hipótesis es la más probable."
            )