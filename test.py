from os import PRIO_USER
import socket
import struct


def check_socks5_proxy_with_auth(
    proxy_host,
    proxy_port,
    username,
    password,
    target_host="httpbin.org",
    target_port=80,
    timeout=10,
):
    """
    Проверяет работоспособность SOCKS5-прокси с обязательной аутентификацией.

    Args:
        proxy_host (str): Хост прокси-сервера.
        proxy_port (int): Порт прокси-сервера.
        username (str): Имя пользователя.
        password (str): Пароль.
        target_host (str): Тестовый хост для проверки (по умолчанию 'httpbin.org').
        target_port (int): Порт тестового хоста (по умолчанию 80).
        timeout (int): Таймаут соединения в секундах.

    Returns:
        bool: True, если прокси работает, иначе False.
    """
    try:
        # Создаем сокет
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Подключаемся к прокси
        sock.connect((proxy_host, proxy_port))
        print(f"Connected to proxy at {proxy_host}:{proxy_port}")

        # Шаг 1: Выбор метода аутентификации
        # Отправляем только метод с логином/паролем (0x02)
        sock.send(b"\x05\x01\x02")  # Версия 5, 1 метод: с логином/паролем

        # Получаем выбранный метод
        response = sock.recv(2)
        print(f"Received greeting response: {response}")
        if not response or response[0] != 0x05:
            print("Invalid SOCKS5 greeting")
            return False

        selected_method = response[1]
        if selected_method != 0x02:
            print("Proxy does not support username/password authentication")
            return False  # Прокси не поддерживает аутентификацию

        # Шаг 2: Аутентификация
        # Формируем сообщение аутентификации
        auth_msg = (
            b"\x01"
            + bytes([len(username)])
            + username.encode()
            + bytes([len(password)])
            + password.encode()
        )
        sock.send(auth_msg)

        # Получаем ответ аутентификации
        auth_response = sock.recv(2)
        print(f"Received authentication response: {auth_response}")
        if auth_response != b"\x01\x00":
            print("Authentication failed")
            return False  # Авторизация не удалась

        # Шаг 3: Установка соединения с целевым хостом
        # Преобразуем домен в IP
        target_ip = socket.gethostbyname(target_host)
        addr_bytes = socket.inet_aton(target_ip)
        port_bytes = struct.pack(">H", target_port)

        # Формируем CONNECT запрос
        connect_request = (
            b"\x05"  # Версия SOCKS5
            + b"\x01"  # Команда CONNECT
            + b"\x00"  # Зарезервировано
            + b"\x01"  # Тип адреса - IPv4
            + addr_bytes
            + port_bytes
        )
        sock.send(connect_request)

        # Получаем ответ на CONNECT
        response = sock.recv(4)
        print(f"Received CONNECT response: {response}")
        if len(response) < 4 or response[0] != 0x05 or response[1] != 0x00:
            print("CONNECT request failed")
            return False  # Ошибка при установке соединения

        # Пропускаем BND.ADDR и BND.PORT
        # (Сервер возвращает связанный адрес, который нас не интересует)

        # Шаг 4: Отправка HTTP-запроса
        http_request = (
            f"GET /ip HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n"
        ).encode()
        sock.send(http_request)

        # Чтение ответа
        response_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk

        # Проверка ответа
        print(f"Received HTTP response: {response_data}")

        return b'"origin":' in response_data

    except Exception as e:
        print(f"Ошибка: {e}")
        return False
    finally:
        sock.close()


# Пример использования
if __name__ == "__main__":
    proxy_host = "localhost"
    proxy_port = 1080
    username = "user"
    password = "kg5CV9e9oVGvebj5"

    result = check_socks5_proxy_with_auth(
        proxy_host, proxy_port, username=username, password=password
    )

    if result:
        print("Прокси работает корректно.")
    else:
        print("Прокси не работает.")
