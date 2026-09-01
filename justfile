# justfile — atajos de comandos para el proyecto hashid
# Uso: just <nombre-del-atajo>, ej. "just test"

# Instala/actualiza dependencias
install:
    uv sync

# Corre todos los tests
test:
    uv run pytest -v

# Corre un hash de ejemplo (bcrypt) para verificar rápido que todo anda
demo:
    uv run hashid identify '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'

# Modo interactivo
run:
    uv run hashid interactive

# Linter (ruff), reporta problemas de estilo sin modificar nada
lint:
    uv run ruff check .

# Limpia archivos generados (cache de pytest, __pycache__)
clean:
    Remove-Item -Recurse -Force .pytest_cache -ErrorAction SilentlyContinue
    Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force