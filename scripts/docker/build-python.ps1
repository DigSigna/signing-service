Write-Host "Building Python-FastAPI Template..." -ForegroundColor Cyan

$TemplatePath = ".\templates\template-python-fastapi"
Write-Host "Building from: $TemplatePath" -ForegroundColor Yellow

# 2. Build Docker con el contexto correcto
Write-Host "2. Building Docker image..." -ForegroundColor Yellow
docker build -f "$TemplatePath\Dockerfile" -t template-python-fastapi "$TemplatePath"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Python-FastAPI Template built successfully!" -ForegroundColor Green
Write-Host "Image: template-python-fastapi" -ForegroundColor White
Write-Host "To run: docker run -p 8000:8000 -e ENVIRONMENT=development template-python-fastapi" -ForegroundColor White