package jwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// JWT структура для работы с JWT токенами
type JWT struct {
	privateKey []byte
	publicKey  []byte
}

// NewJWT создает новый экземпляр JWT с переданными ключами
func NewJWT(privateKey []byte, publicKey []byte) *JWT {
	return &JWT{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// NewJWTFromSecrets создает новый экземпляр JWT из строковых секретов
func NewJWTFromSecrets(privateKeyStr, publicKeyStr string) *JWT {
	return &JWT{
		privateKey: []byte(privateKeyStr),
		publicKey:  []byte(publicKeyStr),
	}
}

// Create создает JWT токен с переданными данными и временем жизни
func (j *JWT) Create(ttl time.Duration, content interface{}) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["dat"] = content             // Our custom data.
	claims["exp"] = now.Add(ttl).Unix() // The expiration time after which the token must be disregarded.
	claims["iat"] = now.Unix()          // The time at which the token was issued.
	claims["nbf"] = now.Unix()          // The time before which the token must be disregarded.

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

// Validate валидирует JWT токен и возвращает данные из него
func (j *JWT) Validate(token string) (interface{}, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)
	if err != nil {
		return nil, fmt.Errorf("validate: parse key: %w", err)
	}

	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}

		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("validate: invalid")
	}

	return claims["dat"], nil
}

// GenerateTokens создает access и refresh токены
func (j *JWT) GenerateTokens(data interface{}, accessTTL time.Duration, refreshTTL time.Duration) (accessToken string, refreshToken string, err error) {
	// Access token lives for 15 minutes
	accessToken, err = j.Create(accessTTL, data)
	if err != nil {
		return "", "", fmt.Errorf("create access token: %w", err)
	}

	// Refresh token lives for 30 days
	refreshToken, err = j.Create(refreshTTL, data)
	if err != nil {
		return "", "", fmt.Errorf("create refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}
