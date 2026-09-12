# Proyecto: Cifrado y Descifrado César / Atbash

Sistema web para cifrar y descifrar mensajes usando los métodos clásicos
**César** y **Atbash**, sobre un alfabeto configurable por el usuario
(basado en códigos ASCII o en un conjunto de símbolos arbitrario).

El descifrado es **100% automático**: el sistema determina por sí mismo
si el mensaje fue cifrado con César (y con qué desplazamiento) o con
Atbash, usando **análisis de frecuencias de letras** — la técnica de
criptoanálisis que popularizó Al-Kindi en el siglo IX. El usuario nunca
elige el método al descifrar; solo pega el texto cifrado y el sistema
entrega la única línea correcta.

## Estructura del proyecto

```
cifrado_proyecto/
├── crypto_engine.py   # Lógica de cifrado, descifrado y criptoanálisis (documentado)
├── app.py             # Interfaz web (Streamlit)
├── requirements.txt   # Dependencias
└── README.md          # Este archivo
```

## Ejecutar en tu computadora

```bash
pip install -r requirements.txt
streamlit run app.py
```

Se abrirá automáticamente en tu navegador (usualmente en http://localhost:8501).

## Publicar el sitio gratis en la web (Streamlit Community Cloud)

1. Crea un repositorio en GitHub (puede ser público o privado) y sube estos
   4 archivos (`app.py`, `crypto_engine.py`, `requirements.txt`, `README.md`).
2. Entra a https://share.streamlit.io/ e inicia sesión con tu cuenta de GitHub
   (es gratuito).
3. Haz clic en **"New app"**, selecciona tu repositorio, la rama (`main`) y
   como archivo principal indica `app.py`.
4. Haz clic en **"Deploy"**. En un par de minutos tendrás una URL pública
   del tipo `https://tu-app.streamlit.app` que puedes compartir en el
   proyecto.

> Alternativa: también puedes desplegarlo en **Hugging Face Spaces**
> (https://huggingface.co/spaces) eligiendo el SDK "Streamlit", el proceso
> es equivalente (subir los mismos archivos).

## Enlaces a entregar

Recuerda que la rúbrica pide DOS ligas:
1. La liga a la **app funcionando** (la URL de Streamlit Cloud / Hugging Face).
2. La liga al **código documentado** (el repositorio de GitHub donde subiste
   estos archivos). Puedes dejarlo como repositorio privado y agregar a tu
   profesor como colaborador si necesitas que el código no sea público —
   esto también cuenta como "documentación de manera segura", ya que solo
   personas autorizadas pueden verlo.

## Fundamento teórico (para tu introducción/desarrollo del reporte)

Abu Yusuf Ya'qub ibn Ishaq al-Kindi, filósofo y matemático árabe del siglo
IX, es considerado el padre del criptoanálisis. En su tratado sobre el
desciframiento de mensajes cifrados describió el **análisis de
frecuencias**: en cualquier idioma, ciertas letras aparecen con una
frecuencia estadística característica (en español, por ejemplo, la "e" y
la "a" son mucho más comunes que la "k" o la "w"). Como los cifrados de
sustitución simple (César y Atbash) sólo reemplazan cada símbolo por otro
de forma consistente, esa distribución de frecuencias del idioma original
"sobrevive" dentro del texto cifrado, sólo que aplicada a otros símbolos.
Esto permite, sin conocer la clave, deducir matemáticamente qué
sustitución se usó — precisamente lo que hace `auto_descifrar()` en este
proyecto mediante la prueba chi-cuadrado. Esta es también la razón por la
que César y Atbash ya **no son viables como métodos de protección de
datos**: son vulnerables a un ataque puramente estadístico, ejecutable en
milisegundos por cualquier computadora moderna, sin necesidad de fuerza
bruta ni de conocer la clave de antemano.
