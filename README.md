Hash Identifier

A command-line tool that looks at a string of text and tells you what kind of hash it probably is — bcrypt, MD5, SHA-256, a JWT, a Cisco password, a blockchain address, and a dozen others.

Built from scratch as a learning project, using CarterPerez-dev's hash-identifier as the starting idea, not as a template to copy.

English | Español

English
What even is a hash, and why would I need to identify one?

Think of a hash as a fingerprint for data. You feed a password, a file, or any chunk of text into a hashing algorithm, and it spits out a fixed-length string of letters and numbers. Feed it the exact same input again, you get the exact same fingerprint. Change a single character, and the fingerprint looks nothing like before.

Websites don't store your actual password — they store its hash. Files get hashed so you can check a download wasn't corrupted or tampered with. Blockchains are basically hashes all the way down. The catch: a hash on its own doesn't announce which algorithm made it. 5d41402abc4b2a76b9719d911017c592 could be MD5, could be NTLM — they happen to produce the same length of output, so the string alone won't tell you.

That's the actual problem this tool solves. If you're a SOC analyst who just pulled a string out of a log file, or someone running a password audit, you need to know what you're looking at before you can do anything useful with it — feed it to a cracking tool, flag it in a report, whatever comes next.

What it does
identify — hand it one hash, get back every algorithm it could plausibly be, ranked by how confident the tool is.
batch — point it at a text file with a hash per line, get results for all of them at once.
interactive — a loop that keeps asking for hashes until you tell it to stop. Good for just poking around.

Every mode can print a color-coded table in your terminal, or spit out JSON/CSV if you want to feed the results into something else — a script, a spreadsheet, a SIEM.

Seeing it in action
$ hashid identify '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'

               Resultados para: $2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G
┏━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Algoritmo ┃ Confianza ┃ Motivo                                                   ┃ Detector       ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ bcrypt    │ alta      │ prefijo `$2b$` — PHC string bcrypt, variante 2b (actual) │ PrefixDetector │
└───────────┴───────────┴──────────────────────────────────────────────────────────┴────────────────┘

(Yes, the output text is in Spanish — that's the language I think in day to day, and I kept it consistent across the whole tool. The code, comments, and architecture underneath are all readable regardless of what language you speak; nothing about the design depends on it.)

A messier example — one where the tool genuinely isn't sure:

$ hashid identify "5d41402abc4b2a76b9719d911017c592" --format json
[
  {
    "algorithm": "MD5",
    "confidence": "medium",
    "reason": "32 caracteres hexadecimales — comparte largo con NTLM y MD4",
    "detector_name": "HexLengthDetector"
  },
  {
    "algorithm": "NTLM",
    "confidence": "medium",
    ...
  },
  {
    "algorithm": "MD4",
    "confidence": "low",
    ...
  }
]

That's deliberate, not a limitation I'm hiding. MD5 and NTLM produce identical-length output — there's no way to tell them apart from the string alone, so the tool says exactly that instead of guessing and pretending it's sure.

Installing it

You'll need Python 3.11 or newer, and uv (a fast Python package manager — think pip, but quicker and it also handles virtual environments for you).

bash
git clone https://github.com/YOUR_USERNAME/hash-identifier.git
cd hash-identifier
uv sync

That last command reads the project's dependency list and sets up an isolated environment with everything it needs. Takes a few seconds.

Using it
bash
# One hash
uv run hashid identify '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'

# A file full of hashes, one per line
uv run hashid batch hashes.txt

# Same, but save the results as JSON instead of printing them
uv run hashid batch hashes.txt --format json --output results.json

# Keep feeding it hashes one at a time
uv run hashid interactive

A Windows-specific gotcha worth knowing: PowerShell treats $ inside double quotes as the start of a variable. Since most hash prefixes use $ (bcrypt, Argon2, Unix crypt formats...), wrapping your hash in double quotes will silently mangle it before it even reaches the tool. Use single quotes instead — '$2b$12$...' — and you'll be fine. I lost a good chunk of a session figuring that one out, so it's documented here to save you the same headache.

How it's built

The short version: instead of one giant function with a long chain of if/elif checks for every hash format (which is how the project I started from does it), each format gets its own small class — a Detector — that only knows how to recognize one thing. A bcrypt detector, a JWT detector, a Cisco Type 7 detector, and so on. A motor runs all of them against your input and collects whatever they find.

The upside: adding a new format later means writing one new class, not editing a 300-line function and hoping I don't break the five formats already living inside it. Whether that trade-off was worth it for a project this size is a fair question — but it's the kind of decision I wanted to make on purpose and be able to explain, not something I backed into.

Full write-up of every session, including two or three bugs I hit and how I tracked them down, lives in docs/Hash_Identifier_Documentacion.docx.

Running the tests
bash
uv run pytest -v

38 tests as of this writing, covering every detector plus the CLI itself.

Credit

Conceptually inspired by CarterPerez-dev/Cybersecurity-Projects — specifically the foundations/hash-identifier learning module. I used it to understand the problem space, then built this with a different architecture, more supported formats, and three usage modes instead of one. None of the original code is reused here.

License

MIT — see LICENSE.

Español
¿Qué es un hash, y para qué querría identificar uno?

Pensá un hash como una huella digital de un dato. Le das una contraseña, un archivo, o cualquier texto a un algoritmo de hashing, y te devuelve un string de largo fijo hecho de letras y números. Si le das exactamente el mismo dato de nuevo, te da exactamente la misma huella. Si cambiás un solo carácter, la huella no se parece en nada a la anterior.

Los sitios web no guardan tu contraseña real — guardan su hash. Los archivos se hashean para poder verificar que una descarga no se corrompió o fue manipulada. Las blockchains son, en el fondo, hashes por todos lados. El problema: un hash por sí solo no te dice qué algoritmo lo generó. 5d41402abc4b2a76b9719d911017c592 podría ser MD5, podría ser NTLM — ambos producen salidas del mismo largo, así que el string solo no alcanza para saberlo.

Ese es el problema real que resuelve esta herramienta. Si sos analista de un SOC y sacaste un string de un log, o estás auditando contraseñas, necesitás saber qué tenés adelante antes de poder hacer algo útil con eso — pasárselo a una herramienta de cracking, marcarlo en un informe, lo que sea que siga.

Qué hace
identify — le das un hash, te devuelve todos los algoritmos que podría ser, ordenados por qué tan segura está la herramienta de cada uno.
batch — le apuntás a un archivo de texto con un hash por línea, te da resultados de todos a la vez.
interactive — un loop que sigue pidiendo hashes hasta que le decís que pare. Sirve para ir probando cosas sueltas.

Cada modo puede imprimir una tabla con colores en tu terminal, o darte JSON/CSV si querés meter los resultados en otra cosa — un script, una planilla, un SIEM.

Viéndolo en acción
$ hashid identify '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'

               Resultados para: $2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G
┏━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Algoritmo ┃ Confianza ┃ Motivo                                                   ┃ Detector       ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ bcrypt    │ alta      │ prefijo `$2b$` — PHC string bcrypt, variante 2b (actual) │ PrefixDetector │
└───────────┴───────────┴──────────────────────────────────────────────────────────┴────────────────┘

Un ejemplo más interesante — uno donde la herramienta realmente no está segura:

$ hashid identify "5d41402abc4b2a76b9719d911017c592" --format json
[
  {
    "algorithm": "MD5",
    "confidence": "medium",
    "reason": "32 caracteres hexadecimales — comparte largo con NTLM y MD4",
    "detector_name": "HexLengthDetector"
  },
  {
    "algorithm": "NTLM",
    "confidence": "medium",
    ...
  },
  {
    "algorithm": "MD4",
    "confidence": "low",
    ...
  }
]

Eso es a propósito, no es una limitación que esté escondiendo. MD5 y NTLM producen salidas del mismo largo — no hay forma de distinguirlos solo mirando el string, así que la herramienta dice exactamente eso en vez de adivinar y hacerse la segura.

Instalación

Necesitás Python 3.11 o más nuevo, y uv (un gestor de paquetes de Python rápido — como pip, pero más veloz y que además maneja los entornos virtuales por vos).

bash
git clone https://github.com/TU_USUARIO/hash-identifier.git
cd hash-identifier
uv sync

Ese último comando lee la lista de dependencias del proyecto y arma un entorno aislado con todo lo necesario. Tarda unos segundos.

Uso
bash
# Un solo hash
uv run hashid identify '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'

# Un archivo con muchos hashes, uno por línea
uv run hashid batch hashes.txt

# Lo mismo, pero guardando el resultado en JSON en vez de imprimirlo
uv run hashid batch hashes.txt --format json --output resultado.json

# Loop pidiendo hashes uno por uno
uv run hashid interactive

Un detalle de Windows que vale la pena conocer: PowerShell trata el $ dentro de comillas dobles como el inicio de una variable. Como la mayoría de los prefijos de hash usan $ (bcrypt, Argon2, formatos crypt de Unix...), envolver tu hash en comillas dobles lo va a arruinar en silencio antes de que le llegue a la herramienta. Usá comillas simples en su lugar — '$2b$12$...' — y no vas a tener problema. Perdí buena parte de una sesión entera dándome cuenta de esto, así que lo dejo documentado acá para que no te pase lo mismo.

Cómo está construido

La versión corta: en vez de una función gigante con una cascada de if/elif para cada formato de hash (que es como lo resuelve el proyecto del que partí), cada formato tiene su propia clase chica — un Detector — que solo sabe reconocer una cosa. Un detector de bcrypt, uno de JWT, uno de Cisco Type 7, y así. Un motor corre todos contra tu input y junta lo que cada uno encuentra.

La ventaja: agregar un formato nuevo más adelante significa escribir una clase nueva, no editar una función de 300 líneas con la esperanza de no romper los cinco formatos que ya viven ahí adentro. Si ese trade-off valía la pena para un proyecto de este tamaño es una pregunta válida — pero es el tipo de decisión que quise tomar a propósito y poder explicar, no algo en lo que caí sin pensarlo.

La bitácora completa de cada sesión, incluidos dos o tres bugs que encontré y cómo los rastreé, vive en docs/Hash_Identifier_Documentacion.docx.

Correr los tests
bash
uv run pytest -v

38 tests al momento de escribir esto, cubriendo cada detector más la CLI.

Crédito

Inspirado conceptualmente en CarterPerez-dev/Cybersecurity-Projects — específicamente el módulo educativo foundations/hash-identifier. Lo usé para entender el problema, y después construí esto con una arquitectura distinta, más formatos soportados, y tres modos de uso en vez de uno. No se reusa nada del código original.

Licencia

MIT — ver LICENSE.
