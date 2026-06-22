# Comandos para publicar SEB-Light en GitHub

## Opcion A: Si ya tienes el repo creado en GitHub
git remote add origin git@github.com:amurlaniakea/seblight.git
git branch -M main
git push -u origin main

## Opcion B: Crear el repo desde la terminal (necesita gh CLI o token)
# 1. Crear repo en GitHub via web: https://github.com/new
#    Nombre: seblight
#    Descripcion: Sovereign Execution Broker (Python) - Certificate-bound authority for agentic command execution
#    Publico
#    NO anadir README (ya tenemos uno)

# 2. Luego:
git remote add origin git@github.com:amurlaniakea/seblight.git
git branch -M main
git push -u origin main

## Opcion C: Usar HTTPS con token
# git remote add origin https://github.com/amurlaniakea/seblight.git
# git branch -M main
# git push -u origin main
# (pedira username + token)
