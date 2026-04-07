@echo off
chcp 65001 >nul
echo =============================================
echo   AuthMaster 安装脚本 (Windows)
echo =============================================
echo.

:: 检查 Docker
where docker >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [错误] 未安装 Docker，请先安装 Docker Desktop
    echo   下载: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)

:: 检查 Docker 是否运行
docker info >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [错误] Docker 未运行，请先启动 Docker Desktop
    pause
    exit /b 1
)

echo [1/3] 启动数据库服务 (PostgreSQL + Redis)...
docker compose up -d postgres redis

echo.
echo [2/3] 等待数据库就绪...
timeout /t 10 /nobreak >nul

echo.
echo [3/3] 安装 Python 依赖 (可选，不用 Docker 时使用)...
if exist requirements.txt (
    pip install -r requirements.txt
    echo.
    echo 安装完成！运行以下命令启动:
    echo   python main_sso.py
    echo 或直接用 Docker 完整启动:
    echo   docker compose up
) else (
    echo   Docker 环境已就绪！
    echo   运行: docker compose up
)

echo.
echo =============================================
echo   安装完成！
echo =============================================
echo.
echo 启动方式:
echo   方式一 (Docker):   docker compose up
echo   方式二 (本地 Python): python main_sso.py
echo.
echo 访问: http://localhost:8000
echo 文档: http://localhost:8000/docs
echo.
pause
