import os
import tempfile
import time
import unittest
import uuid


# Ensure config reads a test-only database path before importing app/config modules.
_TEST_DB_FILE = os.path.join(tempfile.gettempdir(), f"mi_proyecto_test_{uuid.uuid4().hex}.db")
os.environ["DATABASE_PATH"] = _TEST_DB_FILE
os.environ["SECRET_KEY"] = "this-is-a-very-long-test-secret-key-1234567890"
os.environ["CORS_ORIGINS"] = "http://localhost:8080"
os.environ["TRUSTED_HOSTS"] = "localhost,127.0.0.1,api"
os.environ["SESSION_COOKIE_SAMESITE"] = "Lax"
os.environ["SESSION_COOKIE_SECURE"] = "false"

from app import create_app  # noqa: E402
from routes import auth as auth_routes  # noqa: E402


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(_TEST_DB_FILE)
        except FileNotFoundError:
            pass

    def setUp(self):
        self.client = self.app.test_client()
        self.origin_headers = {"Origin": "http://localhost:8080"}

    def _register_user(self):
        unique = uuid.uuid4().hex[:10]
        payload = {
            "email": f"{unique}@example.com",
            "username": f"u{unique}",
            "firstName": "Secure",
            "lastName": "User",
            "password": "abc123",
        }
        response = self.client.post(
            "/api/auth/register",
            json=payload,
            headers=self.origin_headers,
        )
        self.assertEqual(response.status_code, 201)
        return response.get_json()

    def _get_csrf_token(self):
        response = self.client.get("/api/auth/me")
        self.assertEqual(response.status_code, 200)
        data = response.get_json() or {}
        token = data.get("csrfToken")
        self.assertIsInstance(token, str)
        self.assertGreaterEqual(len(token), 16)
        return token

    def test_blocks_patch_without_csrf_token(self):
        self._register_user()

        response = self.client.patch(
            "/api/profile/me",
            json={"firstName": "Secure", "lastName": "User", "avatarUrl": "", "coverUrl": ""},
            headers=self.origin_headers,
        )

        self.assertEqual(response.status_code, 403)
        data = response.get_json() or {}
        self.assertEqual(data.get("error", {}).get("code"), "csrf_blocked")

    def test_allows_patch_with_valid_csrf_token(self):
        self._register_user()
        csrf_token = self._get_csrf_token()

        response = self.client.patch(
            "/api/profile/me",
            json={"firstName": "Secure", "lastName": "User", "avatarUrl": "", "coverUrl": ""},
            headers={**self.origin_headers, "X-CSRF-Token": csrf_token},
        )

        self.assertEqual(response.status_code, 200)

    def test_blocks_php_extension_in_media_url(self):
        self._register_user()
        csrf_token = self._get_csrf_token()

        response = self.client.patch(
            "/api/profile/me",
            json={
                "firstName": "Secure",
                "lastName": "User",
                "avatarUrl": "https://evil.example/shell.php",
                "coverUrl": "",
            },
            headers={**self.origin_headers, "X-CSRF-Token": csrf_token},
        )

        self.assertEqual(response.status_code, 400)
        data = response.get_json() or {}
        self.assertEqual(data.get("error", {}).get("code"), "validation_error")

    def test_blocks_php_payload_in_fake_png_data_url(self):
        self._register_user()
        csrf_token = self._get_csrf_token()

        response = self.client.patch(
            "/api/profile/me",
            json={
                "firstName": "Secure",
                "lastName": "User",
                "avatarUrl": "data:image/png;base64,PD9waHAgZWNobyAxOz8+",
                "coverUrl": "",
            },
            headers={**self.origin_headers, "X-CSRF-Token": csrf_token},
        )

        self.assertEqual(response.status_code, 400)
        data = response.get_json() or {}
        self.assertEqual(data.get("error", {}).get("code"), "validation_error")

    def test_allows_valid_minimal_png_data_url(self):
        self._register_user()
        csrf_token = self._get_csrf_token()

        response = self.client.patch(
            "/api/profile/me",
            json={
                "firstName": "Secure",
                "lastName": "User",
                "avatarUrl": "data:image/png;base64,iVBORw0KGgo=",
                "coverUrl": "",
            },
            headers={**self.origin_headers, "X-CSRF-Token": csrf_token},
        )

        self.assertEqual(response.status_code, 200)

    def test_blocks_untrusted_host_header(self):
        response = self.client.get(
            "/api/health",
            headers={"Host": "evil.example"},
        )

        self.assertEqual(response.status_code, 400)
        data = response.get_json() or {}
        self.assertIn(data.get("error", {}).get("code"), {"bad_host", "bad_request"})

    def test_invalidates_session_on_user_agent_change(self):
        self._register_user()
        csrf_token = self._get_csrf_token()

        # Same session cookie but different user-agent should invalidate session.
        response = self.client.patch(
            "/api/profile/me",
            json={"firstName": "Secure", "lastName": "User", "avatarUrl": "", "coverUrl": ""},
            headers={
                **self.origin_headers,
                "X-CSRF-Token": csrf_token,
                "User-Agent": "attacker-bot/1.0",
            },
        )

        self.assertEqual(response.status_code, 401)
        data = response.get_json() or {}
        self.assertEqual(data.get("error", {}).get("code"), "unauthorized")

    def test_totp_can_be_enabled_and_required_on_login(self):
        creds = self._register_user()
        csrf_token = self._get_csrf_token()

        setup_response = self.client.post(
            "/api/auth/2fa/setup",
            json={},
            headers={**self.origin_headers, "X-CSRF-Token": csrf_token},
        )
        self.assertEqual(setup_response.status_code, 200)
        setup_data = setup_response.get_json() or {}
        secret = setup_data.get("twoFactor", {}).get("secret")
        qr_data_url = setup_data.get("twoFactor", {}).get("qrDataUrl")
        self.assertIsInstance(secret, str)
        self.assertIsInstance(qr_data_url, str)
        self.assertTrue(qr_data_url.startswith("data:image/png;base64,"))

        code = auth_routes._totp_code(secret, int(time.time()))
        enable_response = self.client.post(
            "/api/auth/2fa/enable",
            json={"code": code},
            headers={**self.origin_headers, "X-CSRF-Token": csrf_token},
        )
        self.assertEqual(enable_response.status_code, 200)

        self.client.post("/api/auth/logout", headers=self.origin_headers)

        login_response = self.client.post(
            "/api/auth/login",
            json={"username": creds["user"]["username"], "password": "abc123"},
            headers=self.origin_headers,
        )
        self.assertEqual(login_response.status_code, 202)
        login_data = login_response.get_json() or {}
        self.assertTrue(login_data.get("twoFactorRequired"))

        verify_response = self.client.post(
            "/api/auth/2fa/verify-login",
            json={"code": auth_routes._totp_code(secret, int(time.time()))},
            headers=self.origin_headers,
        )
        self.assertEqual(verify_response.status_code, 200)

    def test_totp_login_rejects_invalid_code(self):
        creds = self._register_user()
        csrf_token = self._get_csrf_token()

        setup_response = self.client.post(
            "/api/auth/2fa/setup",
            json={},
            headers={**self.origin_headers, "X-CSRF-Token": csrf_token},
        )
        secret = (setup_response.get_json() or {}).get("twoFactor", {}).get("secret")
        self.assertIsInstance(secret, str)

        code = auth_routes._totp_code(secret, int(time.time()))
        self.client.post(
            "/api/auth/2fa/enable",
            json={"code": code},
            headers={**self.origin_headers, "X-CSRF-Token": csrf_token},
        )
        self.client.post("/api/auth/logout", headers=self.origin_headers)

        self.client.post(
            "/api/auth/login",
            json={"username": creds["user"]["username"], "password": "abc123"},
            headers=self.origin_headers,
        )

        verify_response = self.client.post(
            "/api/auth/2fa/verify-login",
            json={"code": "000000"},
            headers=self.origin_headers,
        )
        self.assertEqual(verify_response.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
