# -*- coding: utf-8 -*-
"""
crypto_engine.py
=================

Motor de cifrado / descifrado para los métodos César y Atbash, construido
sobre un ALFABETO PERSONALIZABLE (conjunto de caracteres definido por el
usuario, esté o no contenido dentro del rango estándar de códigos ASCII).

Incluye además un módulo de CRIPTOANÁLISIS AUTOMÁTICO basado en análisis
de frecuencias de letras, técnica que se atribuye al matemático árabe
Abu Yusuf Ya'qub ibn Ishaq al-Kindi (siglo IX, tratado "Manuscrito sobre
el descifrado de mensajes criptográficos").

-----------------------------------------------------------------------
LÍMITE IMPORTANTE QUE DEBES CONOCER (y que puedes citar en tu reporte):
-----------------------------------------------------------------------
El análisis de frecuencias SOLO funciona cuando detrás del cifrado hay
lenguaje natural. Si el mensaje original es ruido puro (símbolos al azar,
patrones como "ABABAB" o "1234432112344321", o una contraseña sin
palabras reales), NINGÚN algoritmo -este u otro cualquiera- puede saber
con certeza matemática cuál de todos los desplazamientos posibles es el
"correcto", porque el texto descifrado correctamente no se ve más
"legítimo" que cualquier otro descifrado incorrecto. Esto es un límite
de información (relacionado con la "distancia de unicidad" de Shannon),
no una limitación de programación.

Por eso este módulo:
  1. Intenta detectar automáticamente la respuesta correcta combinando
     tres señales (palabras reales incrustadas, cobertura alfabética y
     frecuencia de letras).
  2. Cuando el mensaje SÍ tiene señal de lenguaje real (aunque esté mezclado
     con símbolos, como "Hola_Mundo2026!"), acierta de forma confiable.
  3. Cuando el mensaje es ruido puro sin ninguna palabra reconocible, lo
     declara honestamente como AMBIGUO y muestra las mejores alternativas
     en vez de inventar una respuesta con falsa seguridad.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Tuple


# ---------------------------------------------------------------------------
# 1. FRECUENCIAS DE REFERENCIA (español)
# ---------------------------------------------------------------------------
FRECUENCIAS_ESPANOL = {
    "a": 12.53, "b": 1.42, "c": 4.68, "d": 5.86, "e": 13.68, "f": 0.69,
    "g": 1.01, "h": 0.70, "i": 6.25, "j": 0.44, "k": 0.02, "l": 4.97,
    "m": 3.15, "n": 6.71, "o": 8.68, "p": 2.51, "q": 0.88, "r": 6.87,
    "s": 7.98, "t": 4.63, "u": 3.93, "v": 0.90, "w": 0.02, "x": 0.22,
    "y": 0.90, "z": 0.52, "ñ": 0.31,
}

# ---------------------------------------------------------------------------
# 1.b DICCIONARIOS DE PALABRAS COMUNES (español + inglés/técnico)
#     Se usan para detectar palabras REALES incrustadas dentro de una
#     cadena, aunque estén rodeadas de símbolos, números o mayúsculas
#     (p. ej. reconocer "Crypto", "Engine" y "Test" dentro de
#     "Crypto$Engine#Test").
# ---------------------------------------------------------------------------
PALABRAS_COMUNES_ESPANOL = {
    "de", "la", "el", "en", "y", "a", "los", "las", "un", "una", "que",
    "es", "por", "con", "para", "no", "se", "su", "al", "lo", "como",
    "mas", "más", "pero", "sus", "le", "ya", "o", "este", "esta", "son",
    "entre", "cuando", "todo", "ser", "muy", "sin", "sobre", "hasta",
    "hay", "donde", "quien", "desde", "nos", "durante", "todos", "uno",
    "dos", "tres", "les", "ni", "contra", "otros", "ese", "eso", "ante",
    "ellos", "e", "esto", "mi", "antes", "algunos", "unos", "yo", "otro",
    "otras", "otra", "tanto", "esa", "estos", "mucho", "quienes", "nada",
    "muchos", "cual", "poco", "ella", "estar", "estas", "algunas", "algo",
    "nosotros", "mis", "tu", "tus", "te", "ti", "hola", "mundo", "buenas",
    "tardes", "profesor", "prueba", "clase", "sol", "luz", "mar", "paz",
    "vida", "amor", "agua", "fuego", "tierra", "sistema", "cifrado",
    "atbash", "cesar", "césar", "extraña", "lorem", "ipsum", "seguridad",
    "computo", "cómputo", "informacion", "información", "mensaje", "clave",
    "codigo", "código", "programa", "python",
}

PALABRAS_COMUNES_INGLES = {
    "the", "and", "test", "engine", "crypto", "password", "secure", "system",
    "code", "data", "user", "admin", "hello", "world", "is", "of", "in", "to",
    "for", "with", "encrypt", "decrypt", "cipher", "key", "hash", "login",
    "server", "client", "network", "file", "folder", "app", "web", "cloud",
}

PALABRAS_COMUNES = PALABRAS_COMUNES_ESPANOL | PALABRAS_COMUNES_INGLES

# Extrae "corridas" de letras (a-z, incluye acentos/ñ) de cualquier cadena,
# ignorando dígitos y símbolos como separadores. Así "Crypto$Engine#Test"
# produce ["Crypto", "Engine", "Test"] en vez de un solo token inválido.
_PATRON_PALABRAS = re.compile(r"[A-Za-zÁÉÍÓÚÑÜáéíóúñü]+")


# ---------------------------------------------------------------------------
# 2. ALFABETO PERSONALIZADO
# ---------------------------------------------------------------------------
class Alfabeto:
    """Conjunto ORDENADO y SIN REPETICIONES de caracteres usado como dominio
    de cifrado. Puede construirse desde un rango ASCII/Unicode o desde una
    cadena arbitraria (incluyendo símbolos fuera del ASCII estándar)."""

    def __init__(self, caracteres: List[str]):
        if len(caracteres) < 2:
            raise ValueError("El alfabeto debe tener al menos 2 caracteres distintos.")
        if len(set(caracteres)) != len(caracteres):
            raise ValueError("El alfabeto no puede tener caracteres repetidos.")
        self.caracteres = caracteres
        self._indice = {c: i for i, c in enumerate(caracteres)}

    def __len__(self) -> int:
        return len(self.caracteres)

    def indice_de(self, c: str) -> int:
        return self._indice[c]

    def caracter_en(self, i: int) -> str:
        return self.caracteres[i % len(self.caracteres)]

    def contiene(self, c: str) -> bool:
        return c in self._indice

    @classmethod
    def generar_desde_ascii(cls, codigo_inicio: int, codigo_fin: int) -> "Alfabeto":
        if codigo_inicio >= codigo_fin:
            raise ValueError("El código de inicio debe ser menor que el código final.")
        return cls([chr(c) for c in range(codigo_inicio, codigo_fin + 1)])

    @classmethod
    def desde_cadena(cls, cadena: str) -> "Alfabeto":
        vistos = []
        for c in cadena:
            if c not in vistos:
                vistos.append(c)
        return cls(vistos)

    @classmethod
    def ascii_imprimible(cls) -> "Alfabeto":
        return cls.generar_desde_ascii(32, 126)


# ---------------------------------------------------------------------------
# 3. CIFRADO / DESCIFRADO
# ---------------------------------------------------------------------------
def cifrar_cesar(texto: str, alfabeto: Alfabeto, desplazamiento: int) -> str:
    """Cifra `texto` con César. Los caracteres fuera del alfabeto (incluidos
    saltos de línea) se dejan sin modificar, para soportar texto multilínea."""
    resultado = []
    for c in texto:
        if alfabeto.contiene(c):
            nuevo_indice = alfabeto.indice_de(c) + desplazamiento
            resultado.append(alfabeto.caracter_en(nuevo_indice))
        else:
            resultado.append(c)
    return "".join(resultado)


def descifrar_cesar(texto: str, alfabeto: Alfabeto, desplazamiento: int) -> str:
    return cifrar_cesar(texto, alfabeto, -desplazamiento)


def cifrar_atbash(texto: str, alfabeto: Alfabeto) -> str:
    """Atbash: cada carácter se sustituye por su 'espejo' dentro del alfabeto."""
    n = len(alfabeto)
    resultado = []
    for c in texto:
        if alfabeto.contiene(c):
            indice_espejo = n - 1 - alfabeto.indice_de(c)
            resultado.append(alfabeto.caracter_en(indice_espejo))
        else:
            resultado.append(c)
    return "".join(resultado)


def descifrar_atbash(texto: str, alfabeto: Alfabeto) -> str:
    return cifrar_atbash(texto, alfabeto)  # Atbash es simétrico


# ---------------------------------------------------------------------------
# 4. CRIPTOANÁLISIS AUTOMÁTICO (estilo Al-Kindi + verificación léxica)
# ---------------------------------------------------------------------------
def _chi_cuadrado(texto: str) -> float:
    """Chi-cuadrado NORMALIZADO (chi2 / letras analizadas) entre las
    frecuencias observadas y las esperadas del español. Menor = mejor."""
    letras = [c for c in texto.lower() if c in FRECUENCIAS_ESPANOL]
    total = len(letras)
    if total == 0:
        return 999.0

    conteo = {letra: 0 for letra in FRECUENCIAS_ESPANOL}
    for c in letras:
        conteo[c] += 1

    chi2 = 0.0
    for letra, freq_esperada_pct in FRECUENCIAS_ESPANOL.items():
        esperado = (freq_esperada_pct / 100.0) * total
        observado = conteo[letra]
        if esperado > 0:
            chi2 += ((observado - esperado) ** 2) / esperado

    return chi2 / total


def _cobertura_alfabetica(texto: str) -> float:
    """Proporción de caracteres que son letras reconocidas del español (o
    espacio) respecto al total. Se usa SOLO como señal de respaldo del
    chi-cuadrado (para penalizar candidatos que 'rompen' letras en símbolos
    raros). Deliberadamente NO se cuentan dígitos ni guiones/símbolos como
    'buenos', aunque aparezcan en identificadores como 'Hola_Mundo2026!':
    ese tipo de cadenas ya se reconoce de forma mucho más fiable por medio
    de las palabras reales incrustadas (`_puntaje_palabras_comunes`). Si
    también contáramos aquí los símbolos como 'válidos', dos candidatos muy
    distintos podrían empatar en cobertura por pura coincidencia de
    posiciones de espacio/símbolo, perdiendo poder de discriminación."""
    if not texto:
        return 0.0
    significativos = sum(1 for c in texto.lower() if c in FRECUENCIAS_ESPANOL or c == " ")
    return significativos / len(texto)


def _palabras_incrustadas(texto: str) -> List[str]:
    """Extrae todas las 'corridas' de letras dentro de la cadena, sin
    importar que estén pegadas a números, símbolos o mayúsculas.
    Ej: 'Crypto$Engine#Test' -> ['Crypto', 'Engine', 'Test']"""
    return _PATRON_PALABRAS.findall(texto)


def _puntaje_palabras_comunes(texto: str) -> Tuple[float, int]:
    """Puntúa cuántas 'palabras' incrustadas en el texto coinciden con
    palabras reales y frecuentes (español + inglés/técnico).

    Devuelve una tupla (puntaje_ponderado, palabras_fuertes):
      - puntaje_ponderado: las palabras de 1-2 letras valen 0.25 (pueden
        aparecer por azar, sobre todo si se repiten muchas veces).
      - palabras_fuertes: cuenta SOLO palabras de 3+ letras, que son una
        señal mucho más confiable de que el texto realmente está en
        español/inglés (una palabra de 3+ letras casi no aparece por
        casualidad en un texto mal descifrado)."""
    puntaje = 0.0
    fuertes = 0
    for p in _palabras_incrustadas(texto):
        p_normal = p.lower()
        if p_normal in PALABRAS_COMUNES:
            if len(p_normal) >= 3:
                puntaje += 1.0
                fuertes += 1
            else:
                puntaje += 0.25
    return puntaje, fuertes


@dataclass
class Candidato:
    texto: str
    metodo: str
    parametro: int
    chi2: float
    palabras: float          # puntaje ponderado (débiles cuentan 0.25)
    palabras_fuertes: int    # cuántas palabras reales de 3+ letras se hallaron
    cobertura: float

    @property
    def puntaje(self) -> float:
        return (self.palabras * 8.0) + (self.cobertura * 3.0) - self.chi2


@dataclass
class ResultadoAutoDescifrado:
    texto_descifrado: str
    metodo_detectado: str          # "CESAR" o "ATBASH"
    parametro: int                   # desplazamiento usado (0 si es Atbash)
    puntaje_chi_cuadrado: float
    palabras_reconocidas: float
    cobertura: float
    confianza: str = "ALTA"          # "ALTA" o "BAJA"
    alternativas: List[Tuple[str, str, int]] = field(default_factory=list)
    # cada alternativa: (texto, metodo, parametro)


def auto_descifrar(texto_cifrado: str, alfabeto: Alfabeto) -> ResultadoAutoDescifrado:
    """
    Determina automáticamente -SIN intervención humana- si el texto fue
    cifrado con César (y con qué desplazamiento) o con Atbash.

    IMPORTANTE: cuando el mensaje no contiene ninguna palabra real
    reconocible (p. ej. es ruido de símbolos o un patrón sin sentido), el
    resultado se marca con `confianza = "BAJA"` y se incluyen las mejores
    alternativas. Esto es una limitación matemática inherente al
    criptoanálisis por frecuencias (ver docstring del módulo), no un error
    del programa: sin lenguaje real detrás, no existe forma de saber cuál
    desplazamiento es el correcto.
    """
    candidatos: List[Candidato] = []
    n = len(alfabeto)

    for despl in range(1, n):
        texto = descifrar_cesar(texto_cifrado, alfabeto, despl)
        puntaje_pal, fuertes = _puntaje_palabras_comunes(texto)
        candidatos.append(Candidato(
            texto, "CESAR", despl,
            _chi_cuadrado(texto),
            puntaje_pal,
            fuertes,
            _cobertura_alfabetica(texto),
        ))

    texto_atbash = descifrar_atbash(texto_cifrado, alfabeto)
    puntaje_pal_a, fuertes_a = _puntaje_palabras_comunes(texto_atbash)
    candidatos.append(Candidato(
        texto_atbash, "ATBASH", 0,
        _chi_cuadrado(texto_atbash),
        puntaje_pal_a,
        fuertes_a,
        _cobertura_alfabetica(texto_atbash),
    ))

    candidatos.sort(key=lambda c: c.puntaje, reverse=True)
    mejor = candidatos[0]

    # Nivel de confianza: se requiere AL MENOS UNA palabra real de 3+ letras
    # en algún candidato. Acumular muchas coincidencias débiles (palabras de
    # 1-2 letras, que pueden repetirse por azar en un patrón) NO cuenta.
    hay_palabras_fuertes = any(c.palabras_fuertes >= 1 for c in candidatos)
    confianza = "ALTA" if hay_palabras_fuertes else "BAJA"

    alternativas = [
        (c.texto, c.metodo, c.parametro) for c in candidatos[1:4]
    ] if confianza == "BAJA" else []

    return ResultadoAutoDescifrado(
        texto_descifrado=mejor.texto,
        metodo_detectado=mejor.metodo,
        parametro=mejor.parametro,
        puntaje_chi_cuadrado=mejor.chi2,
        palabras_reconocidas=mejor.palabras,
        cobertura=mejor.cobertura,
        confianza=confianza,
        alternativas=alternativas,
    )