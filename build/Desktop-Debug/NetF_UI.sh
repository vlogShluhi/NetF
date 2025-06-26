#!/bin/bash
# Получаем абсолютный путь к директории
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PATH="$APP_DIR/NetF"

# Экспортируем ВСЕ необходимые переменные
export DISPLAY=":0"
export XAUTHORITY="/run/user/1000/.mutter-Xwaylandauth.CLJT82"
export QT_QPA_PLATFORM="xcb"
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
export XDG_RUNTIME_DIR="/run/user/1000"
export HOME="/home/shluha"  # Критически важно!

# Проверка X-сервера
if ! xhost >/dev/null 2>&1; then
    echo "Ошибка: Нет доступа к X-серверу" >&2
    exit 1
fi

# Запуск с сохранением окружения
pkexec --user shluha env \
    DISPLAY="$DISPLAY" \
    XAUTHORITY="$XAUTHORITY" \
    QT_QPA_PLATFORM="$QT_QPA_PLATFORM" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    HOME="$HOME" \
    "$APP_PATH"
