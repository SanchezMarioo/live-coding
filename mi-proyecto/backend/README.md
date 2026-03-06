# Backend Flask

API REST con Flask, SQLite y sesion por cookie httpOnly.

## Endpoints

- `GET /api/health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/google`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/auth/2fa/setup`
- `POST /api/auth/2fa/enable`
- `POST /api/auth/2fa/disable`
- `POST /api/auth/2fa/verify-login`
- `GET /api/messages?limit=50&offset=0&category=all`
- `POST /api/messages`
- `PUT /api/messages/:id`
- `DELETE /api/messages/:id`

## Seguridad aplicada

- Password hasheada con `werkzeug.security.generate_password_hash`.
- Validacion y sanitizacion en backend.
- Errores JSON controlados sin stack traces en respuestas.
- Rutas protegidas por sesion en cookie `httpOnly`.
- Verificacion de token de Google en backend (no confiar en frontend).
- CSRF token obligatorio en operaciones de escritura autenticadas.
- Validacion de host permitido (`TRUSTED_HOSTS`) para evitar Host header attacks.
- Sesion ligada a huella de `User-Agent` para mitigar reutilizacion de cookie robada.

## Variables de entorno

- `GOOGLE_CLIENT_ID`: client id OAuth 2.0 web de Google para validar `id_token`.
- `TRUSTED_HOSTS`: hosts permitidos para peticiones API (default: `localhost,127.0.0.1,api`).

## Levantar con Docker

Desde la raiz del proyecto:

```bash
docker-compose up --build
```

Frontend: `http://localhost:8080`
API: `http://localhost:3000`

## Tests de seguridad

Ejecutar tests automatizados de CSRF y validacion de media:

```bash
python -m unittest discover -s tests -v
```
