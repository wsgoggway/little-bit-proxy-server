use base64::decode;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SOCKS_VERSION: u8 = 0x05;
const AUTH_METHOD_NONE: u8 = 0x00;
const AUTH_METHOD_USERPASS: u8 = 0x02;
const AUTH_STATUS_SUCCESS: u8 = 0x00;
const AUTH_STATUS_FAILURE: u8 = 0xFF;

#[derive(Clone)]
struct Config {
    users: HashMap<String, String>,
}

async fn handle_socks5_client(
    mut client: TcpStream,
    config: Arc<Config>,
) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0u8; 1024];

    // Шаг 1: Приветствие (Greeting)
    let n = client.read(&mut buffer).await?;
    if n < 3 || buffer[0] != SOCKS_VERSION {
        return Err("Invalid SOCKS5 greeting".into());
    }

    // Проверяем, поддерживается ли аутентификация
    let auth_method = if buffer[2] == AUTH_METHOD_USERPASS {
        AUTH_METHOD_USERPASS
    } else {
        AUTH_METHOD_NONE
    };
    if auth_method == AUTH_METHOD_NONE {
        eprintln!("auth method none disable");
        return Err("Invalid authentication method".into());
    }

    // Отправляем выбранный метод аутентификации
    client.write_all(&[SOCKS_VERSION, auth_method]).await?;

    // Шаг 2: Аутентификация
    let n = client.read(&mut buffer).await?;
    if n < 3 || buffer[0] != 0x01 {
        return Err("Invalid authentication method".into());
    }
    let username_len = buffer[1] as usize;
    let username = String::from_utf8(buffer[2..2 + username_len].to_vec())?;
    let password_len = buffer[2 + username_len] as usize;
    let password =
        String::from_utf8(buffer[3 + username_len..3 + username_len + password_len].to_vec())?;

    // проверяем есть ли такой пользователь
    //
    if config.users.contains_key(&username) {
        let current_user_password = config.users.get(&username).unwrap();

        // сверяем пароли
        //
        if password != *current_user_password {
            client.write_all(&[0x01, AUTH_STATUS_FAILURE]).await?;
            eprintln!("Auth failed username: {username}, password: {password} wrong password");
            return Err("Authentication failed".into());
        }
    } else {
        client.write_all(&[0x01, AUTH_STATUS_FAILURE]).await?;
        eprintln!("Auth failed username: {username}, password: {password} user not found");
        return Err("Authentication failed".into());
    }

    // Успешная аутентификация
    client.write_all(&[0x01, AUTH_STATUS_SUCCESS]).await?;

    // Шаг 3: Запрос на подключение
    let n = client.read(&mut buffer).await?;
    if n < 7 || buffer[0] != SOCKS_VERSION || buffer[1] != 0x01 {
        return Err("Invalid SOCKS5 request".into());
    }

    // Извлекаем адрес и порт
    let target_addr = match buffer[3] {
        0x01 => {
            // IPv4
            format!("{}.{}.{}.{}", buffer[4], buffer[5], buffer[6], buffer[7])
        }
        0x03 => {
            // Доменное имя
            let len = buffer[4] as usize;
            String::from_utf8(buffer[5..5 + len].to_vec())?
        }
        _ => {
            return Err("Unsupported address type".into());
        }
    };
    let target_port = u16::from_be_bytes([buffer[n - 2], buffer[n - 1]]);
    let target_addr_str = format!("{}:{}", target_addr, target_port);

    println!(
        "user: {}, {} -> {}",
        username,
        client.peer_addr().unwrap(),
        target_addr_str
    );

    // Подключаемся к целевому серверу
    let mut target = TcpStream::connect(target_addr_str).await?;

    // Отправляем клиенту успешный ответ
    client
        .write_all(&[SOCKS_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // Передача данных между клиентом и целевым сервером
    let (mut client_reader, mut client_writer) = client.split();
    let (mut target_reader, mut target_writer) = target.split();
    let client_to_target = tokio::io::copy(&mut client_reader, &mut target_writer);
    let target_to_client = tokio::io::copy(&mut target_reader, &mut client_writer);
    tokio::select! {
        _ = client_to_target => {},
        _ = target_to_client => {},
    }

    Ok(())
}

async fn handle_http_connect(
    mut client: TcpStream,
    config: Arc<Config>,
) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0u8; 4096];

    // Читаем запрос от клиента
    let n = client.read(&mut buffer).await?;
    if n == 0 {
        return Err("Empty CONNECT request".into());
    }

    // Преобразуем запрос в строку
    let request = String::from_utf8_lossy(&buffer[..n]);
    let lines: Vec<&str> = request.lines().collect();
    if lines.is_empty() {
        return Err("Invalid CONNECT request".into());
    }

    // Парсим первую строку запроса
    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "CONNECT" {
        return Err("Invalid CONNECT request line".into());
    }

    let target = parts[1];
    let target_parts: Vec<&str> = target.split(':').collect();
    if target_parts.len() != 2 {
        return Err("Invalid target in CONNECT request".into());
    }

    let host = target_parts[0];
    let port: u16 = target_parts[1].parse()?;
    let target_addr = format!("{}:{}", host, port);

    // Проверяем авторизацию
    let mut authorized = false;
    for line in &lines[1..] {
        if line.starts_with("Proxy-Authorization:") {
            let auth_header = line.trim_start_matches("Proxy-Authorization:").trim();
            if let Some(credentials) = auth_header.strip_prefix("Basic ") {
                if let Ok(decoded) = decode(credentials) {
                    let creds = String::from_utf8(decoded)?;
                    let parts: Vec<&str> = creds.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        let username = parts[0];
                        let password = parts[1];
                        if let Some(stored_password) = config.users.get(username) {
                            if *stored_password == password {
                                authorized = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if !authorized {
        // Возвращаем ошибку 407 Proxy Authentication Required
        let response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Access to the proxy\"\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Err("Proxy authentication required".into());
    }

    // Подключаемся к целевому серверу
    let mut target_stream = match TcpStream::connect(target_addr).await {
        Ok(stream) => stream,
        Err(_) => {
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client.write_all(response.as_bytes()).await?;
            return Err("Failed to connect to target server".into());
        }
    };

    // Отправляем успешный ответ клиенту
    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    client.write_all(response.as_bytes()).await?;

    // Передача данных между клиентом и целевым сервером
    let (mut client_reader, mut client_writer) = client.split();
    let (mut target_reader, mut target_writer) = target_stream.split();
    let client_to_target = tokio::io::copy(&mut client_reader, &mut target_writer);
    let target_to_client = tokio::io::copy(&mut target_reader, &mut client_writer);
    tokio::select! {
        _ = client_to_target => {},
        _ = target_to_client => {},
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Arc::new(Config {
        users: HashMap::from([("user".to_string(), "kg5CV9e9oVGvebj5".to_string())]), // openssl rand -base64 12
    });

    let listener = TcpListener::bind("0.0.0.0:1080").await?;
    println!("Proxy server is running on port 1080");

    while let Ok((client, _)) = listener.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            let mut buffer = [0u8; 1];
            if client.peek(&mut buffer).await.is_ok() {
                if buffer[0] == SOCKS_VERSION {
                    // Это SOCKS5-запрос
                    if let Err(e) = handle_socks5_client(client, config).await {
                        eprintln!("SOCKS5 error: {}", e);
                    }
                } else {
                    // Это HTTP-запрос
                    if let Err(e) = handle_http_connect(client, config).await {
                        eprintln!("HTTP error: {}", e);
                    }
                }
            }
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn test_socks5_greeting() {
        // Создаем фиктивный клиент и сервер
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 2];
            client.read_exact(&mut buffer).await.unwrap();

            // Отправляем ответ на приветствие
            client
                .write_all(&[SOCKS_VERSION, AUTH_METHOD_NONE])
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&[SOCKS_VERSION, 1, AUTH_METHOD_NONE])
            .await
            .unwrap();

        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();

        assert_eq!(response, [SOCKS_VERSION, AUTH_METHOD_NONE]);
    }

    #[tokio::test]
    async fn test_socks5_authentication_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = Arc::new(Config {
            users: HashMap::from([("testuser".to_string(), "password123".to_string())]),
        });

        tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            handle_socks5_client(client, config).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();

        // Отправляем приветствие
        client
            .write_all(&[SOCKS_VERSION, 1, AUTH_METHOD_USERPASS])
            .await
            .unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [SOCKS_VERSION, AUTH_METHOD_USERPASS]);

        // Отправляем аутентификацию
        let auth_request = [
            0x01, // Версия аутентификации
            8,    // Длина имени пользователя
            b't', b'e', b's', b't', b'u', b's', b'e', b'r', // Имя пользователя
            11,   // Длина пароля
            b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', b'1', b'2', b'3', // Пароль
        ];
        client.write_all(&auth_request).await.unwrap();

        let mut auth_response = [0u8; 2];
        client.read_exact(&mut auth_response).await.unwrap();
        assert_eq!(auth_response, [0x01, AUTH_STATUS_SUCCESS]);
    }

    #[tokio::test]
    async fn test_socks5_authentication_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = Arc::new(Config {
            users: HashMap::from([("testuser".to_string(), "password123".to_string())]),
        });

        tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            handle_socks5_client(client, config).await.unwrap_err();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();

        // Отправляем приветствие
        client
            .write_all(&[SOCKS_VERSION, 1, AUTH_METHOD_USERPASS])
            .await
            .unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [SOCKS_VERSION, AUTH_METHOD_USERPASS]);

        // Отправляем неверные учетные данные
        let auth_request = [
            0x01, // Версия аутентификации
            8,    // Длина имени пользователя
            b't', b'e', b's', b't', b'u', b's', b'e', b'r', // Имя пользователя
            5,    // Длина пароля
            b'w', b'r', b'o', b'n', b'g', // Неверный пароль
        ];
        client.write_all(&auth_request).await.unwrap();

        let mut auth_response = [0u8; 2];
        client.read_exact(&mut auth_response).await.unwrap();
        assert_eq!(auth_response, [0x01, AUTH_STATUS_FAILURE]);
    }

    #[tokio::test]
    async fn test_http_proxy_with_authentication() {
        // Запускаем прокси-сервер
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = Arc::new(Config {
            users: HashMap::from([("user".to_string(), "password".to_string())]),
        });

        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let config_clone = config.clone();
                tokio::spawn(async move {
                    handle_http_connect(client, config_clone).await.unwrap();
                });
            }
        });

        // Клиент подключается к прокси
        let mut client = TcpStream::connect(addr).await.unwrap();

        // Формируем CONNECT-запрос с аутентификацией
        let credentials = base64::encode("user:password");
        let connect_request = format!(
        "CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org\r\nProxy-Authorization: Basic {}\r\n\r\n",
        credentials
    );
        client.write_all(connect_request.as_bytes()).await.unwrap();

        // Получаем ответ от прокси
        let mut buffer = [0u8; 1024];
        let n = client.read(&mut buffer).await.unwrap();
        let response = String::from_utf8_lossy(&buffer[..n]);
        assert!(response.contains("HTTP/1.1 200 Connection Established"));
    }

    #[tokio::test]
    async fn test_http_proxy_authentication_failure() {
        // Запускаем прокси-сервер
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = Arc::new(Config {
            users: HashMap::from([("user".to_string(), "password".to_string())]),
        });

        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let config_clone = config.clone();
                tokio::spawn(async move {
                    handle_http_connect(client, config_clone).await.unwrap_err();
                });
            }
        });

        // Клиент подключается к прокси
        let mut client = TcpStream::connect(addr).await.unwrap();

        // Формируем CONNECT-запрос без аутентификации
        let connect_request = "CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n";
        client.write_all(connect_request.as_bytes()).await.unwrap();

        // Получаем ответ от прокси
        let mut buffer = [0u8; 1024];
        let n = client.read(&mut buffer).await.unwrap();
        let response = String::from_utf8_lossy(&buffer[..n]);
        assert!(response.contains("HTTP/1.1 407 Proxy Authentication Required"));
    }
}
