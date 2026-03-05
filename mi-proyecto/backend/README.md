# Backend Flask

API REST con Flask, SQLite y sesion por cookie httpOnly.

## Endpoints

- `GET /api/health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/google`
- `POST /api/auth/logout`
- `GET /api/auth/me`
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

## Variables de entorno

- `GOOGLE_CLIENT_ID`: client id OAuth 2.0 web de Google para validar `id_token`.

## Levantar con Docker

Desde la raiz del proyecto:

```bash
docker-compose up --build
```

Frontend: `http://localhost:8080`
API: `http://localhost:3000`
