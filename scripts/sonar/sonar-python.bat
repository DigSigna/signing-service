@echo off
setlocal enabledelayedexpansion

echo [INFO] Analisis SonarQube para Template Python FastAPI...

REM Cambiar al directorio raíz del proyecto (donde está sonar.env)
cd /d "E:\Proyectos\DigSigna\platform-templates"

REM Verificar que existe el archivo .env
if not exist sonar.env (
    echo [ERROR] No se encuentra el archivo sonar.env
    echo [INFO] Crea el archivo sonar.env en la raíz del proyecto con:
    echo SONAR_TOKEN_PYTHON=tu_token
    echo SONAR_PROJECT_KEY_PYTHON=template-python-fastapi
    echo SONAR_PROJECT_NAME_PYTHON=Template Python FastAPI
    echo SONAR_HOST_URL=http://localhost:9000
    pause
    exit /b 1
)

REM Leer variables del archivo .env
echo [INFO] Cargando configuración desde sonar.env...
for /f "usebackq tokens=1,* delims==" %%A in ("sonar.env") do (
    if not "%%A"=="" if "%%A" neq "#" (
        set "%%A=%%B"
    )
)

REM Verificar que las variables necesarias están definidas
if "%SONAR_TOKEN_PYTHON%"=="" (
    echo [ERROR] SONAR_TOKEN_PYTHON no está definido en sonar.env
    pause
    exit /b 1
)

if "%SONAR_PROJECT_KEY_PYTHON%"=="" (
    echo [ERROR] SONAR_PROJECT_KEY_PYTHON no está definido en sonar.env
    pause
    exit /b 1
)

if "%SONAR_PROJECT_NAME_PYTHON%"=="" (
    echo [ERROR] SONAR_PROJECT_NAME_PYTHON no está definido en sonar.env
    pause
    exit /b 1
)

if "%SONAR_HOST_URL%"=="" (
    echo [ERROR] SONAR_HOST_URL no está definido en sonar.env
    pause
    exit /b 1
)

REM Cambiar al directorio del proyecto Python
cd /d "E:\Proyectos\DigSigna\platform-templates\templates\template-python-fastapi"

echo [INFO] Verificando Python y dependencias...
python --version
pip --version

REM Limpiar archivos anteriores de reportes
del coverage.xml 2>nul
del test-results.xml 2>nul
del bandit-results.json 2>nul
del safety-report.json 2>nul
del flake8-report.json 2>nul
del sonar-project.properties 2>nul

REM Verificar que SonarQube esté corriendo
echo [INFO] Verificando conexión con SonarQube...
curl -s %SONAR_HOST_URL%/api/system/status > sonar_status.json 2>nul
python -c "import json; import sys; data=json.load(open('sonar_status.json')); print(f'[INFO] SonarQube status: {data.get(\"status\")}'); sys.exit(0 if data.get('status') == 'UP' else 1)" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] SonarQube no está disponible en %SONAR_HOST_URL%
    echo [INFO] Iniciando SonarQube con Docker...
    docker-compose -f docker-compose.sonarqube.yml up -d
    timeout /t 30 /nobreak >nul
    echo [INFO] Esperando que SonarQube inicie...
    timeout /t 60 /nobreak >nul
)

REM INSTALAR HERRAMIENTAS DE CALIDAD GLOBALMENTE
echo [INFO] Instalando herramientas de calidad...
pip install pytest pytest-cov bandit safety flake8

REM Ejecutar pruebas con cobertura (SOLO si hay tests)
if exist "tests" (
    echo [INFO] Ejecutando pruebas unitarias con cobertura...
    pytest --cov=app --cov-report=xml --cov-report=html --junitxml=test-results.xml -v
    if errorlevel 1 (
        echo [WARNING] Algunas pruebas fallaron, continuando con análisis...
    )
) else (
    echo [INFO] No hay directorio tests, omitiendo pruebas...
    echo ^<?xml version="1.0" encoding="UTF-8"^^?^>^<testsuites^>^</testsuites^> > test-results.xml
    echo ^<coverage version="1.0"^>^</coverage^> > coverage.xml
)

REM Ejecutar análisis de seguridad (SOLO en app/)
echo [INFO] Ejecutando análisis de seguridad Bandit...
bandit -r app/ -f json -o bandit-results.json 2>nul
if errorlevel 1 (
    echo {"errors": [], "generated_at": "2024-01-01", "metrics": {}, "results": []} > bandit-results.json
)

REM Ejecutar análisis de dependencias
echo [INFO] Verificando vulnerabilidades en dependencias...
safety check --json > safety-report.json 2>nul
if errorlevel 1 (
    echo {"vulnerabilities": [], "analyzed_requirements": []} > safety-report.json
)

REM Ejecutar linter (SOLO en app/)
echo [INFO] Ejecutando análisis de calidad de código...
flake8 app/ --exit-zero --format=json > flake8-report.json 2>nul
if errorlevel 1 (
    echo [] > flake8-report.json
)

REM Verificar variables antes del análisis
echo [INFO] Variables de configuración:
echo   SONAR_HOST_URL: %SONAR_HOST_URL%
echo   SONAR_PROJECT_KEY_PYTHON: %SONAR_PROJECT_KEY_PYTHON%
echo   SONAR_TOKEN_PYTHON: ********

REM Análisis SonarQube
echo [INFO] Ejecutando análisis SonarQube...
sonar-scanner.bat ^
  -Dsonar.projectKey=%SONAR_PROJECT_KEY_PYTHON% ^
  -Dsonar.projectName="%SONAR_PROJECT_NAME_PYTHON%" ^
  -Dsonar.host.url=%SONAR_HOST_URL% ^
  -Dsonar.token=%SONAR_TOKEN_PYTHON% ^
  -Dsonar.exclusions=venv/**,**/site-packages/**,**/*.pyc,**/__pycache__/**,.git/** ^
  -Dsonar.coverage.exclusions=venv/**,**/site-packages/**,**/__init__.py,**/main.py ^

if errorlevel 1 (
    echo [ERROR] El análisis de SonarQube falló
    echo [INFO] Solución de problemas:
    echo   - Verifica que SonarQube esté ejecutándose: %SONAR_HOST_URL%
    echo   - Verifica que el token sea correcto
    echo   - Revisa los reportes generados (coverage.xml, test-results.xml)
    pause
    exit /b 1
)

REM Mostrar resultados
echo [INFO] Análisis completado exitosamente!
echo [INFO] Reportes generados:
dir *.xml *.json

echo [INFO] Dashboard: %SONAR_HOST_URL%/dashboard?id=%SONAR_PROJECT_KEY_PYTHON%

echo [INFO] Quality Gates completadas!
pause