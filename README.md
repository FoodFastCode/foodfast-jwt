# FoodFast JWT Library

Библиотека для работы с JWT токенами в проекте FoodFast.

## Использование

### Инициализация

```go
import "foodfast-jwt"

// Из байтовых ключей
jwtService := jwt.NewJWT(privateKeyBytes, publicKeyBytes)

// Из строковых секретов (для Docker/Kubernetes)
jwtService := jwt.NewJWTFromSecrets(privateKeyStr, publicKeyStr)
```

### Создание токенов

```go
// Создание одного токена
token, err := jwtService.Create(15*time.Minute, userData)

// Создание access и refresh токенов
accessToken, refreshToken, err := jwtService.GenerateTokens(userData)
```

### Валидация токенов

```go
userData, err := jwtService.Validate(token)
if err != nil {
    // Обработка ошибки
}
```

## Конфигурация

Библиотека поддерживает два способа передачи ключей:

1. **Файлы** - для локальной разработки
2. **Секреты** - для продакшена (Docker/Kubernetes)

### Переменные окружения

- `JWT_PRIVATE_KEY` - приватный ключ в формате PEM
- `JWT_PUBLIC_KEY` - публичный ключ в формате PEM # foodfast-jwt
