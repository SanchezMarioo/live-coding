// ========================================
// ESTADO GLOBAL
// ========================================
let currentUser = null;
let allMessages = [];
let editingMessageId = null;
let registeredUsers = []; // Array de usuarios registrados
let selectedCategoryFilter = 'all';
let selectedMessageLimit = 0;
let pendingAuthUser = null;
let twoFactorState = null;
let googleAuthIntent = 'login';
let googleTokenClient = null;
let replyingToMessageId = null;
let isProfileSectionVisible = false;
let isProfileEditing = false;
let currentProfileUsername = null;
let activeProfileData = null;
let activeProfileMessages = [];
let csrfToken = null;
let twoFactorIntent = null;

const ALLOWED_CATEGORIES = ['general', 'anuncios', 'preguntas', 'ideas', 'offtopic'];
const API_BASE = 'http://localhost:3000';
const CATEGORY_LABELS = {
    general: 'General',
    anuncios: 'Anuncios',
    preguntas: 'Preguntas',
    ideas: 'Ideas',
    offtopic: 'Offtopic'
};

// Reemplaza este valor por tu Client ID real de Google Cloud (OAuth 2.0 Web)
const GOOGLE_CLIENT_ID = '484532142714-gas9d18cc01shpk4j2lvsaleut3t00i9.apps.googleusercontent.com';
const TWO_FACTOR_EXPIRY_MS = 3 * 60 * 1000;

function normalizeIdList(values) {
    if (!Array.isArray(values)) return [];
    const normalized = values
        .map(value => Number.parseInt(value, 10))
        .filter(value => Number.isInteger(value) && value > 0);
    return [...new Set(normalized)];
}

function sanitizeImageUrl(value) {
    if (typeof value !== 'string' || value.length === 0) {
        return '';
    }

    const trimmed = value.trim();
    if (trimmed.startsWith('data:image/')) {
        return trimmed;
    }

    if (trimmed.startsWith('https://') || trimmed.startsWith('http://')) {
        return trimmed;
    }

    return '';
}

function ensureSocialFields(user) {
    return {
        ...user,
        friendIds: normalizeIdList(user.friendIds),
        followingIds: normalizeIdList(user.followingIds),
        coverDataUrl: sanitizeImageUrl(user.coverDataUrl || ''),
        avatarDataUrl: sanitizeImageUrl(user.avatarDataUrl || '')
    };
}

function mapApiUser(user) {
    if (!user || typeof user !== 'object') return null;
    return ensureSocialFields({
        id: user.id,
        username: sanitizeString(user.username || '', 20),
        email: sanitizeString(user.email || '', 254),
        firstName: sanitizeString(user.firstName || '', 50),
        lastName: sanitizeString(user.lastName || '', 50),
        avatarDataUrl: sanitizeImageUrl(user.avatarUrl || ''),
        coverDataUrl: sanitizeImageUrl(user.coverUrl || ''),
        twoFactorEnabled: Boolean(user.twoFactorEnabled),
        friendIds: [],
        followingIds: [],
        registeredAt: user.createdAt || new Date().toISOString(),
        loginAt: new Date().toISOString(),
    });
}

function mapApiMessage(message) {
    return {
        id: message.id,
        userId: message.userId,
        parentId: message.parentId || null,
        username: sanitizeString(message.username || '', 20),
        firstName: '',
        lastName: '',
        avatarDataUrl: sanitizeImageUrl(message.avatarUrl || ''),
        authorDisplayName: sanitizeString(message.authorDisplayName || message.username || '', 120),
        category: normalizeCategory(message.category || 'general'),
        text: sanitizeString(message.text || '', 500),
        createdAt: message.createdAt,
        updatedAt: message.updatedAt || message.createdAt,
    };
}

function mapApiProfile(profile) {
    if (!profile || typeof profile !== 'object') return null;

    return ensureSocialFields({
        id: profile.id,
        username: sanitizeString(profile.username || '', 20),
        email: sanitizeString(profile.email || '', 254),
        firstName: sanitizeString(profile.firstName || '', 50),
        lastName: sanitizeString(profile.lastName || '', 50),
        avatarDataUrl: sanitizeImageUrl(profile.avatarUrl || ''),
        coverDataUrl: sanitizeImageUrl(profile.coverUrl || ''),
        friendIds: [],
        followingIds: [],
        registeredAt: profile.createdAt || new Date().toISOString(),
        loginAt: profile.lastLoginAt || new Date().toISOString(),
        contributions: Number.isInteger(profile.contributions) ? profile.contributions : 0,
        level: profile.level || null,
        social: {
            friends: profile.social && Number.isInteger(profile.social.friends) ? profile.social.friends : 0,
            followers: profile.social && Number.isInteger(profile.social.followers) ? profile.social.followers : 0,
            following: profile.social && Number.isInteger(profile.social.following) ? profile.social.following : 0,
            viewerIsFriend: Boolean(profile.social && profile.social.viewerIsFriend),
            viewerFollows: Boolean(profile.social && profile.social.viewerFollows),
        },
    });
}

async function loadActiveProfileContext() {
    if (!currentUser || !isProfileSectionVisible) {
        activeProfileData = null;
        activeProfileMessages = [];
        return;
    }

    const targetUsername = currentProfileUsername || currentUser.username;
    if (!targetUsername) {
        activeProfileData = null;
        activeProfileMessages = [];
        return;
    }

    try {
        const data = await apiRequest(`/api/profile/${encodeURIComponent(targetUsername)}?limit=100&offset=0`, {
            method: 'GET',
            headers: {},
        });

        activeProfileData = mapApiProfile(data.profile);
        activeProfileMessages = Array.isArray(data.messages) ? data.messages.map(mapApiMessage) : [];
    } catch (_error) {
        activeProfileData = null;
        activeProfileMessages = [];
    }
}

async function apiRequest(path, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    const isUnsafeMethod = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
    const extraHeaders = {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
    };
    if (isUnsafeMethod && csrfToken) {
        extraHeaders['X-CSRF-Token'] = csrfToken;
    }

    const response = await fetch(`${API_BASE}${path}`, {
        credentials: 'include',
        ...options,
        headers: extraHeaders,
    });

    let data = null;
    try {
        data = await response.json();
    } catch (_error) {
        data = null;
    }

    if (!response.ok) {
        const message = data && data.error && data.error.message ? data.error.message : `HTTP ${response.status}`;
        throw new Error(message);
    }

    return data;
}

async function hydrateSessionFromBackend() {
    try {
        const data = await apiRequest('/api/auth/me', { method: 'GET' });
        currentUser = mapApiUser(data.user);
        csrfToken = typeof data.csrfToken === 'string' ? data.csrfToken : null;
    } catch (_error) {
        currentUser = null;
        csrfToken = null;
    }
}

async function loadMessagesFromBackend() {
    try {
        const data = await apiRequest('/api/messages?limit=100', { method: 'GET', headers: {} });
        const messages = Array.isArray(data.messages) ? data.messages : [];
        allMessages = messages.map(mapApiMessage);
    } catch (_error) {
        allMessages = [];
    }
}

function setGoogleAuthIntent(intent) {
    googleAuthIntent = intent === 'register' ? 'register' : 'login';
}

function hasGsap() {
    return typeof window.gsap !== 'undefined';
}

function animatePageEntrance() {
    if (!hasGsap()) return;

    gsap.from('nav', {
        y: -40,
        opacity: 0,
        duration: 0.6,
        ease: 'power2.out'
    });

    gsap.from('#publishSection, #messagesList, #emptyMessages', {
        y: 24,
        opacity: 0,
        duration: 0.6,
        stagger: 0.08,
        ease: 'power2.out',
        delay: 0.08
    });
}

function animateModalOpen(selector) {
    if (!hasGsap()) return;
    gsap.fromTo(selector, {
        opacity: 0
    }, {
        opacity: 1,
        duration: 0.2,
        ease: 'power1.out'
    });

    gsap.fromTo(`${selector} .retro-box`, {
        y: 20,
        scale: 0.96,
        opacity: 0
    }, {
        y: 0,
        scale: 1,
        opacity: 1,
        duration: 0.28,
        ease: 'back.out(1.5)'
    });
}

function animateMessageCards() {
    if (!hasGsap()) return;
    gsap.from('#messagesList article', {
        y: 18,
        opacity: 0,
        duration: 0.35,
        stagger: 0.05,
        ease: 'power2.out',
        clearProps: 'transform'
    });
}

// ========================================
// INICIALIZACIÓN
// ========================================
document.addEventListener('DOMContentLoaded', async () => {
    loadFromLocalStorage();
    await hydrateSessionFromBackend();
    await loadMessagesFromBackend();
    
    // Verificar si hay datos antiguos incompatibles
    if (currentUser && registeredUsers.length === 0) {
        console.warn('⚠️ Detectados datos antiguos incompatibles con el nuevo sistema.');
        showNotification('⚠️ Sistema actualizado. Por favor, cierra sesión y regístrate de nuevo.', 'warning');
    }
    
    updateUI();
    renderMessages();
    setupMessageInputListener();
    setupMessageFilters();
    setupProfileListeners();
    initializeGoogleLogin();
    animatePageEntrance();
    initializeRouting();
    renderRoute();
    
    // Debugging info en consola
    console.log('📊 Estado del foro:');
    console.log('  - Usuarios registrados:', registeredUsers.length);
    console.log('  - Mensajes totales:', allMessages.length);
    console.log('  - Sesión actual:', currentUser ? currentUser.username : 'No logueado');
    if (registeredUsers.length > 0) {
        console.log('  - Usuarios:', registeredUsers.map(u => u.username).join(', '));
    }
});

function initializeRouting() {
    window.addEventListener('popstate', () => {
        renderRoute();
    });
}

function navigateTo(path) {
    const profileByUserMatch = typeof path === 'string' ? path.match(/^\/profile\/([a-zA-Z0-9_-]{3,20})$/) : null;
    const safePath = path === '/profile' || profileByUserMatch ? path : '/';

    if (safePath.startsWith('/profile') && !currentUser) {
        showNotification('Debes iniciar sesion para ver /profile.', 'warning');
        openAuthModal('login');
        return;
    }

    if (window.location.pathname !== safePath) {
        window.history.pushState({}, '', safePath);
    }

    renderRoute();
}

function getCurrentRoute() {
    if (window.location.pathname === '/profile') {
        return '/profile';
    }

    const profileByUserMatch = window.location.pathname.match(/^\/profile\/([a-zA-Z0-9_-]{3,20})$/);
    if (profileByUserMatch) {
        return `/profile/${profileByUserMatch[1]}`;
    }

    return '/';
}

async function renderRoute() {
    const route = getCurrentRoute();
    const publishSection = document.getElementById('publishSection');
    const wallSection = document.getElementById('wallSection');

    if (route.startsWith('/profile') && !currentUser) {
        if (window.location.pathname !== '/') {
            window.history.replaceState({}, '', '/');
        }
    }

    const activeRoute = getCurrentRoute();
    isProfileSectionVisible = activeRoute.startsWith('/profile');
    currentProfileUsername = null;
    if (activeRoute.startsWith('/profile/')) {
        currentProfileUsername = activeRoute.replace('/profile/', '');
    }

    if (publishSection) {
        if (currentUser && activeRoute === '/') {
            publishSection.classList.remove('hidden');
        } else {
            publishSection.classList.add('hidden');
        }
    }

    if (wallSection) {
        if (activeRoute === '/') {
            wallSection.classList.remove('hidden');
        } else {
            wallSection.classList.add('hidden');
        }
    }

    await loadActiveProfileContext();
    renderProfileSection();
}

function navigateToUserProfile(username) {
    const safeUsername = sanitizeString(username || '', 20);
    if (!isValidUsername(safeUsername)) {
        showNotification('Usuario de perfil no valido.', 'error');
        return;
    }
    navigateTo(`/profile/${safeUsername}`);
}

// ========================================
// MODAL DE AUTENTICACIÓN
// ========================================

function openAuthModal(type) {
    document.getElementById('authModal').classList.remove('hidden');
    switchAuthTab(type);
    animateModalOpen('#authModal');
}

function closeAuthModal() {
    document.getElementById('authModal').classList.add('hidden');
    document.getElementById('authError').classList.add('hidden');
    document.getElementById('loginForm').reset();
    document.getElementById('registerForm').reset();
}

function switchAuthTab(type) {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const tabLogin = document.getElementById('tabLogin');
    const tabRegister = document.getElementById('tabRegister');
    const authTitle = document.getElementById('authTitle');

    if (type === 'login') {
        setGoogleAuthIntent('login');
        loginForm.classList.remove('hidden');
        registerForm.classList.add('hidden');
        tabLogin.classList.remove('bg-gray-300');
        tabLogin.classList.add('bg-yellow-300');
        tabRegister.classList.remove('bg-yellow-300');
        tabRegister.classList.add('bg-gray-300');
        authTitle.textContent = 'LOGIN';
    } else {
        setGoogleAuthIntent('register');
        registerForm.classList.remove('hidden');
        loginForm.classList.add('hidden');
        tabRegister.classList.remove('bg-gray-300');
        tabRegister.classList.add('bg-yellow-300');
        tabLogin.classList.remove('bg-yellow-300');
        tabLogin.classList.add('bg-gray-300');
        authTitle.textContent = 'REGISTER';
    }
}

function showAuthError(message) {
    const errorEl = document.getElementById('authError');
    errorEl.textContent = message;
    errorEl.classList.remove('hidden');
}

function generateTwoFactorCode() {
    return String(Math.floor(100000 + Math.random() * 900000));
}

function openTwoFactorModal() {
    const modal = document.getElementById('twoFactorModal');
    if (modal) {
        modal.classList.remove('hidden');
        animateModalOpen('#twoFactorModal');
    }
}

function closeTwoFactorModal() {
    const modal = document.getElementById('twoFactorModal');
    if (modal) {
        modal.classList.add('hidden');
    }

    const codeInput = document.getElementById('twoFactorCodeInput');
    if (codeInput) {
        codeInput.value = '';
    }

    const setupPanel = document.getElementById('twoFactorSetupPanel');
    const secretText = document.getElementById('twoFactorSecretText');
    const submitBtn = document.getElementById('twoFactorSubmitBtn');
    const secondaryBtn = document.getElementById('twoFactorSecondaryBtn');
    if (setupPanel) setupPanel.classList.add('hidden');
    if (secretText) secretText.textContent = '-';
    if (submitBtn) submitBtn.textContent = 'VERIFICAR';
    if (secondaryBtn) secondaryBtn.textContent = 'CANCELAR';

    pendingAuthUser = null;
    twoFactorState = null;
    twoFactorIntent = null;
}

function finalizeUserLogin(user) {
    currentUser = ensureSocialFields({
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName || '',
        lastName: user.lastName || '',
        avatarDataUrl: user.avatarDataUrl || '',
        coverDataUrl: user.coverDataUrl || '',
        friendIds: user.friendIds || [],
        followingIds: user.followingIds || [],
        loginAt: new Date().toISOString(),
        registeredAt: user.registeredAt
    });

    saveToLocalStorage();
    closeAuthModal();
    closeTwoFactorModal();
    updateUI();
    renderMessages();
}

function startTwoFactorChallenge(user, provider = 'local') {
    pendingAuthUser = user;
    twoFactorState = {
        code: generateTwoFactorCode(),
        expiresAt: Date.now() + TWO_FACTOR_EXPIRY_MS,
        attempts: 0,
        provider,
        serverVerify: provider === 'local'
    };
    twoFactorIntent = twoFactorState.serverVerify ? 'login' : 'demo';

    const info = document.getElementById('twoFactorInfo');
    if (info) {
        const providerLabel = provider === 'google' ? 'Google' : 'usuario/password';
        info.textContent = `Factor 1 validado (${providerLabel}). Introduce el codigo temporal.`;
    }

    if (!twoFactorState.serverVerify) {
        // Flujo demo legacy para proveedores no locales.
        showNotification(`Codigo 2FA (demo): ${twoFactorState.code}`, 'warning');
    }
    openTwoFactorModal();
}

function resendTwoFactorCode() {
    if (!pendingAuthUser) {
        showNotification('No hay verificacion pendiente.', 'error');
        return;
    }

    const provider = twoFactorState ? twoFactorState.provider : 'local';
    if (twoFactorState && twoFactorState.serverVerify) {
        showNotification('Usa el codigo de tu app autenticadora.', 'info');
        return;
    }
    startTwoFactorChallenge(pendingAuthUser, provider);
}

function handleTwoFactorSecondaryAction() {
    if (twoFactorIntent === 'setup') {
        showNotification('Escanea el QR y escribe el codigo de 6 digitos.', 'info');
        return;
    }
    closeTwoFactorModal();
}

function renderTwoFactorQr(otpauthUrl, qrDataUrl = '') {
    const qrCanvas = document.getElementById('twoFactorQrCanvas');
    const info = document.getElementById('twoFactorInfo');

    if (!qrCanvas) {
        showNotification('No se encontro el canvas QR.', 'error');
        return;
    }

    if (qrDataUrl && qrDataUrl.startsWith('data:image/png;base64,')) {
        const ctx = qrCanvas.getContext('2d');
        const image = new Image();
        image.onload = () => {
            qrCanvas.width = image.width;
            qrCanvas.height = image.height;
            ctx.clearRect(0, 0, qrCanvas.width, qrCanvas.height);
            ctx.drawImage(image, 0, 0);
            if (info) {
                info.textContent = 'Escanea el QR en tu app autenticadora y confirma con el codigo de 6 digitos.';
            }
        };
        image.onerror = () => {
            if (info) {
                info.textContent = 'Error al dibujar QR. Usa la clave manual de abajo.';
            }
        };
        image.src = qrDataUrl;
        return;
    }

    if (!otpauthUrl) {
        if (info) {
            info.textContent = 'No se pudo generar URL de configuracion. Usa la clave manual.';
        }
        return;
    }

    if (!window.QRCode || typeof window.QRCode.toCanvas !== 'function') {
        if (info) {
            info.textContent = 'No se pudo renderizar el QR en este navegador. Usa la clave manual de abajo.';
        }
        return;
    }

    window.QRCode.toCanvas(qrCanvas, otpauthUrl, { width: 200 }, (error) => {
        if (error) {
            console.error('Error renderizando QR 2FA:', error);
            if (info) {
                info.textContent = 'Error al renderizar QR. Usa la clave manual de abajo.';
            }
            return;
        }

        if (info) {
            info.textContent = 'Escanea el QR en tu app autenticadora y confirma con el codigo de 6 digitos.';
        }
    });
}

async function toggleTwoFactorProfile() {
    if (!currentUser) return;
    if (!isViewingOwnProfile(currentUser.username)) {
        showNotification('Solo puedes gestionar tu propio 2FA.', 'error');
        return;
    }

    if (currentUser.twoFactorEnabled) {
        twoFactorIntent = 'disable';
        pendingAuthUser = { username: currentUser.username };
        twoFactorState = {
            code: '',
            expiresAt: Date.now() + TWO_FACTOR_EXPIRY_MS,
            attempts: 0,
            provider: 'local',
            serverVerify: false,
        };
        const setupPanel = document.getElementById('twoFactorSetupPanel');
        const info = document.getElementById('twoFactorInfo');
        const submitBtn = document.getElementById('twoFactorSubmitBtn');
        const secondaryBtn = document.getElementById('twoFactorSecondaryBtn');
        if (setupPanel) setupPanel.classList.add('hidden');
        if (info) info.textContent = 'Introduce tu codigo actual para desactivar 2FA.';
        if (submitBtn) submitBtn.textContent = 'DESACTIVAR';
        if (secondaryBtn) secondaryBtn.textContent = 'CANCELAR';
        openTwoFactorModal();
        return;
    }

    try {
        const data = await apiRequest('/api/auth/2fa/setup', {
            method: 'POST',
            body: JSON.stringify({}),
        });
        const twoFactor = data.twoFactor || {};
        const otpauthUrl = twoFactor.otpauthUrl || '';
        const qrDataUrl = twoFactor.qrDataUrl || '';
        const secret = twoFactor.secret || '';

        twoFactorIntent = 'setup';
        pendingAuthUser = { username: currentUser.username };
        twoFactorState = {
            code: '',
            expiresAt: Date.now() + TWO_FACTOR_EXPIRY_MS,
            attempts: 0,
            provider: 'local',
            serverVerify: false,
        };
        const setupPanel = document.getElementById('twoFactorSetupPanel');
        const info = document.getElementById('twoFactorInfo');
        const submitBtn = document.getElementById('twoFactorSubmitBtn');
        const secondaryBtn = document.getElementById('twoFactorSecondaryBtn');
        const secretText = document.getElementById('twoFactorSecretText');
        const qrCanvas = document.getElementById('twoFactorQrCanvas');

        if (setupPanel) setupPanel.classList.remove('hidden');
        if (info) info.textContent = 'Escanea el QR en tu app autenticadora y confirma con el codigo de 6 digitos.';
        if (submitBtn) submitBtn.textContent = 'ACTIVAR 2FA';
        if (secondaryBtn) secondaryBtn.textContent = 'AYUDA';
        if (secretText) secretText.textContent = secret || '-';

        renderTwoFactorQr(otpauthUrl, qrDataUrl);

        openTwoFactorModal();
    } catch (error) {
        showNotification(error.message || 'No se pudo iniciar configuracion 2FA.', 'error');
    }
}

async function verifyTwoFactorCode(event) {
    event.preventDefault();

    if (!pendingAuthUser || !twoFactorState) {
        showNotification('No hay verificacion 2FA pendiente.', 'error');
        return;
    }

    if (Date.now() > twoFactorState.expiresAt) {
        showNotification('El codigo ha expirado. Reenvialo.', 'error');
        return;
    }

    const input = document.getElementById('twoFactorCodeInput');
    const enteredCode = sanitizeString(input ? input.value : '', 6);
    if (!/^\d{6}$/.test(enteredCode)) {
        showNotification('El codigo debe tener 6 digitos.', 'warning');
        return;
    }

    twoFactorState.attempts += 1;
    if (twoFactorState.attempts > 5) {
        showNotification('Demasiados intentos. Inicia sesion otra vez.', 'error');
        closeTwoFactorModal();
        return;
    }

    if (twoFactorIntent === 'setup') {
        try {
            await apiRequest('/api/auth/2fa/enable', {
                method: 'POST',
                body: JSON.stringify({ code: enteredCode }),
            });
            currentUser.twoFactorEnabled = true;
            closeTwoFactorModal();
            renderProfileSection();
            showNotification('2FA activado correctamente.', 'success');
            return;
        } catch (error) {
            showNotification(error.message || 'Codigo 2FA invalido.', 'error');
            return;
        }
    }

    if (twoFactorIntent === 'disable') {
        try {
            await apiRequest('/api/auth/2fa/disable', {
                method: 'POST',
                body: JSON.stringify({ code: enteredCode }),
            });
            currentUser.twoFactorEnabled = false;
            closeTwoFactorModal();
            renderProfileSection();
            showNotification('2FA desactivado.', 'info');
            return;
        } catch (error) {
            showNotification(error.message || 'Codigo 2FA invalido.', 'error');
            return;
        }
    }

    if (twoFactorState.serverVerify) {
        try {
            const data = await apiRequest('/api/auth/2fa/verify-login', {
                method: 'POST',
                body: JSON.stringify({ code: enteredCode }),
            });
            currentUser = mapApiUser(data.user);
            csrfToken = typeof data.csrfToken === 'string' ? data.csrfToken : null;
            closeAuthModal();
            closeTwoFactorModal();
            updateUI();
            await loadMessagesFromBackend();
            renderMessages();
            showNotification('2FA correcto. Sesion iniciada.', 'success');
            return;
        } catch (error) {
            showNotification(error.message || 'Codigo 2FA incorrecto.', 'error');
            return;
        }
    }

    if (enteredCode !== twoFactorState.code) {
        showNotification('Codigo incorrecto.', 'error');
        return;
    }

    const username = pendingAuthUser.username;
    finalizeUserLogin(pendingAuthUser);
    showNotification(`2FA correcto. Bienvenido, ${escapeHtml(username)}!`, 'success');
}

function initializeGoogleLogin() {
    if (!window.google || !window.google.accounts || !window.google.accounts.oauth2) {
        setTimeout(() => {
            initializeGoogleLogin();
        }, 1000);
        return;
    }

    if (!isConfiguredGoogleClientId()) {
        showNotification('Configura GOOGLE_CLIENT_ID para usar Google.', 'warning');
        return;
    }

    googleTokenClient = window.google.accounts.oauth2.initTokenClient({
        client_id: GOOGLE_CLIENT_ID,
        scope: 'openid email profile',
        callback: async (tokenResponse) => {
            if (!tokenResponse || !tokenResponse.access_token) {
                showAuthError('No se pudo obtener acceso con Google.');
                return;
            }

            try {
                await authenticateWithGoogleToken(tokenResponse.access_token);
            } catch (error) {
                console.error('Error en autenticacion Google:', error);
                showAuthError(error.message || 'No se pudo iniciar sesion con Google.');
            }
        }
    });
}

function startGoogleOAuth(intent = 'login') {
    setGoogleAuthIntent(intent);

    if (!googleTokenClient) {
        initializeGoogleLogin();
    }

    if (!googleTokenClient) {
        showNotification('Google no esta listo. Recarga e intentalo de nuevo.', 'error');
        return;
    }

    googleTokenClient.requestAccessToken({ prompt: 'select_account' });
}

async function fetchGoogleUserProfile(accessToken) {
    const response = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    if (!response.ok) {
        throw new Error(`Google userinfo HTTP ${response.status}`);
    }

    return response.json();
}

async function authenticateWithGoogleToken(credential) {
    const intent = getGoogleAuthIntent();
    const data = await apiRequest('/api/auth/google', {
        method: 'POST',
        body: JSON.stringify({ credential, intent }),
    });

    currentUser = mapApiUser(data.user);
    csrfToken = typeof data.csrfToken === 'string' ? data.csrfToken : null;
    closeAuthModal();
    updateUI();
    await loadMessagesFromBackend();
    renderMessages();
    showNotification('Sesion iniciada con Google', 'success');
}

function getGoogleAuthIntent() {
    if (googleAuthIntent === 'register' || googleAuthIntent === 'login') {
        return googleAuthIntent;
    }

    const registerForm = document.getElementById('registerForm');
    return registerForm && !registerForm.classList.contains('hidden') ? 'register' : 'login';
}

function isConfiguredGoogleClientId() {
    return typeof GOOGLE_CLIENT_ID === 'string' &&
        GOOGLE_CLIENT_ID.includes('.apps.googleusercontent.com') &&
        !GOOGLE_CLIENT_ID.startsWith('TU_GOOGLE_CLIENT_ID');
}

function decodeJwtPayload(token) {
    try {
        const parts = token.split('.');
        if (parts.length < 2) return null;
        const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        const payload = atob(base64);
        return JSON.parse(payload);
    } catch (error) {
        console.error('Error decodificando token de Google:', error);
        return null;
    }
}

function buildUniqueUsername(baseUsername) {
    const normalizedBase = sanitizeString(baseUsername, 20)
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, '')
        .replace(/^[-_]+|[-_]+$/g, '') || 'usergoogle';

    let candidate = normalizedBase.substring(0, 20);
    if (!registeredUsers.some(u => u.username.toLowerCase() === candidate.toLowerCase())) {
        return candidate;
    }

    let counter = 1;
    while (counter < 9999) {
        const suffix = String(counter);
        const sliced = normalizedBase.substring(0, Math.max(3, 20 - suffix.length));
        candidate = `${sliced}${suffix}`;
        if (!registeredUsers.some(u => u.username.toLowerCase() === candidate.toLowerCase())) {
            return candidate;
        }
        counter += 1;
    }

    return `user${Date.now().toString().slice(-6)}`;
}

function handleGoogleCredentialResponse(response) {
    if (!response || !response.credential) {
        showAuthError('No se pudo obtener credenciales de Google.');
        return;
    }

    authenticateWithGoogleToken(response.credential).catch((error) => {
        console.error('Error en autenticacion Google:', error);
        showAuthError(error.message || 'No se pudo iniciar sesion con Google.');
    });
}

function handleGoogleProfile(profile) {
    if (!profile || !profile.email) {
        showAuthError('Perfil de Google inválido.');
        return;
    }

    const email = sanitizeString(profile.email, 254).toLowerCase();
    const googleName = sanitizeString(profile.name || profile.given_name || email.split('@')[0], 20);
    const intent = getGoogleAuthIntent();

    let foundUser = registeredUsers.find(u => u.email.toLowerCase() === email);

    if (intent === 'login' && !foundUser) {
        showAuthError('No existe cuenta Google para este email. Usa "Registrarte con Google".');
        return;
    }

    if (intent === 'register' && foundUser) {
        showAuthError('Este email ya esta registrado. Usa "Iniciar sesion con Google".');
        return;
    }

    if (!foundUser) {
        const username = buildUniqueUsername(googleName);
        foundUser = {
            id: Date.now(),
            username,
            email,
            firstName: sanitizeString(profile.given_name || '', 50),
            lastName: sanitizeString(profile.family_name || '', 50),
            avatarDataUrl: sanitizeImageUrl(profile.picture || ''),
            coverDataUrl: '',
            friendIds: [],
            followingIds: [],
            authProvider: 'google',
            password: null,
            registeredAt: new Date().toISOString()
        };
        registeredUsers.push(foundUser);
    } else if (!foundUser.authProvider) {
        foundUser.authProvider = 'local';
    }

    startTwoFactorChallenge({
        id: foundUser.id,
        username: foundUser.username,
        email: foundUser.email,
        firstName: foundUser.firstName || '',
        lastName: foundUser.lastName || '',
        avatarDataUrl: foundUser.avatarDataUrl || '',
        coverDataUrl: foundUser.coverDataUrl || '',
        friendIds: foundUser.friendIds || [],
        followingIds: foundUser.followingIds || [],
        registeredAt: foundUser.registeredAt
    }, 'google');
}

// ========================================
// AUTENTICACIÓN: LOGIN
// ========================================

async function handleLogin(event) {
    event.preventDefault();
    
    // Obtener y sanitizar valores
    const rawUsername = document.getElementById('loginUsername').value;
    const rawPassword = document.getElementById('loginPassword').value;
    
    const username = sanitizeString(rawUsername, 254);
    const password = sanitizeString(rawPassword, 128);

    // Validaciones estrictas
    if (!username) {
        showAuthError('El campo usuario/email es obligatorio');
        return;
    }

    if (!password) {
        showAuthError('La contraseña es obligatoria');
        return;
    }

    // Validar tipo de dato
    if (typeof username !== 'string' || typeof password !== 'string') {
        showAuthError('Datos inválidos');
        return;
    }

    // Validar longitud mínima
    if (username.length < 3) {
        showAuthError('El usuario/email debe tener al menos 3 caracteres');
        return;
    }

    if (password.length < 6) {
        showAuthError('La contraseña debe tener al menos 6 caracteres');
        return;
    }

    // Detectar contenido malicioso
    if (containsMaliciousContent(username) || containsMaliciousContent(password)) {
        showAuthError('Datos inválidos detectados');
        return;
    }

    try {
        const data = await apiRequest('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password }),
        });

        if (data && data.twoFactorRequired) {
            pendingAuthUser = { username };
            twoFactorState = {
                code: '',
                expiresAt: Date.now() + TWO_FACTOR_EXPIRY_MS,
                attempts: 0,
                provider: 'local',
                serverVerify: true,
            };
            twoFactorIntent = 'login';
            const info = document.getElementById('twoFactorInfo');
            if (info) {
                info.textContent = 'Introduce el codigo de tu app autenticadora para completar el login.';
            }
            openTwoFactorModal();
            return;
        }

        currentUser = mapApiUser(data.user);
        csrfToken = typeof data.csrfToken === 'string' ? data.csrfToken : null;
        closeAuthModal();
        updateUI();
        await loadMessagesFromBackend();
        renderMessages();
        showNotification('Sesion iniciada correctamente', 'success');
    } catch (error) {
        showAuthError(error.message || 'Error al iniciar sesion');
    }
}

// ========================================
// AUTENTICACIÓN: REGISTRO
// ========================================

async function handleRegister(event) {
    event.preventDefault();
    
    // Obtener y sanitizar valores
    const rawEmail = document.getElementById('registerEmail').value;
    const rawFirstName = document.getElementById('registerFirstName').value;
    const rawLastName = document.getElementById('registerLastName').value;
    const rawUsername = document.getElementById('registerUsername').value;
    const rawPassword = document.getElementById('registerPassword').value;
    const rawPasswordConfirm = document.getElementById('registerPasswordConfirm').value;
    
    const email = sanitizeString(rawEmail, 254);
    const firstName = sanitizeString(rawFirstName, 50);
    const lastName = sanitizeString(rawLastName, 50);
    const username = sanitizeString(rawUsername, 20);
    const password = sanitizeString(rawPassword, 128);
    const passwordConfirm = sanitizeString(rawPasswordConfirm, 128);

    // Validación: Tipo de datos
    if (typeof email !== 'string' || typeof firstName !== 'string' || typeof lastName !== 'string' || typeof username !== 'string' || 
        typeof password !== 'string' || typeof passwordConfirm !== 'string') {
        showAuthError('Datos inválidos');
        return;
    }
    if (!firstName) {
        showAuthError('El nombre es obligatorio');
        return;
    }

    if (!lastName) {
        showAuthError('Los apellidos son obligatorios');
        return;
    }


    // Validación: Campos vacíos
    if (!email) {
        showAuthError('El email es obligatorio');
        return;
    }

    if (!username) {
        showAuthError('El nombre de usuario es obligatorio');
        return;
    }

    if (!password) {
        showAuthError('La contraseña es obligatoria');
        return;
    }

    if (!passwordConfirm) {
        showAuthError('Debes confirmar la contraseña');
        return;
    }

    // Validación: Contenido malicioso
    if (containsMaliciousContent(email) || containsMaliciousContent(username) || 
        containsMaliciousContent(password)) {
        showAuthError('Se detectaron caracteres no permitidos');
        return;
    }

    // Validación: Formato de email ESTRICTO
    if (!isValidEmail(email)) {
        showAuthError('Email inválido. Formato correcto: usuario@dominio.com');
        return;
    }

    // Validación: Username ESTRICTO
    if (!isValidUsername(username)) {
        showAuthError('Usuario inválido. Debe tener 3-20 caracteres (letras, números, - o _)');
        return;
    }

    // Validación: Contraseñas coinciden (comparación estricta)
    if (password !== passwordConfirm) {
        showAuthError('Las contraseñas no coinciden exactamente');
        return;
    }

    // Validación: Contraseña fuerte ESTRICTA
    if (!isStrongPassword(password)) {
        showAuthError('Contraseña débil. Min. 6 caracteres con letras y números. Evita contraseñas comunes.');
        return;
    }

    try {
        const data = await apiRequest('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({ email, username, firstName, lastName, password }),
        });
        currentUser = mapApiUser(data.user);
        csrfToken = typeof data.csrfToken === 'string' ? data.csrfToken : null;
        closeAuthModal();
        updateUI();
        await loadMessagesFromBackend();
        renderMessages();
        showNotification('Cuenta creada e inicio de sesion correcto', 'success');
    } catch (error) {
        showAuthError(error.message || 'No se pudo registrar la cuenta');
    }
}

// ========================================
// AUTENTICACIÓN: LOGOUT
// ========================================

async function logout() {
    try {
        await apiRequest('/api/auth/logout', { method: 'POST' });
    } catch (_error) {
        // If backend session is already gone, continue with local cleanup.
    }
    csrfToken = null;
    currentUser = null;
    isProfileSectionVisible = false;
    localStorage.removeItem('foroUser');
    updateUI();
    await loadMessagesFromBackend();
    renderMessages();
    renderProfileSection();
    showNotification('Sesion cerrada correctamente', 'info');
}

// ========================================
// MENSAJES: PUBLICAR
// ========================================

async function handlePublishMessage(event) {
    event.preventDefault();
    
    // Obtener y sanitizar
    const rawText = document.getElementById('messageInput').value;
    const messageText = sanitizeString(rawText, 500);
    const categoryInput = document.getElementById('messageCategory');
    const parentMessage = replyingToMessageId ? allMessages.find(m => String(m.id) === String(replyingToMessageId)) : null;
    const messageCategory = parentMessage
        ? normalizeCategory(parentMessage.category)
        : normalizeCategory(categoryInput ? categoryInput.value : 'general');

    // Validación con función dedicada
    if (!isValidMessage(messageText)) {
        if (!messageText || messageText.length < 3) {
            showNotification('El mensaje debe tener entre 3 y 500 caracteres', 'warning');
        } else if (messageText.length > 500) {
            showNotification('El mensaje no puede exceder 500 caracteres', 'error');
        } else if (containsMaliciousContent(messageText)) {
            showNotification('El mensaje contiene contenido no permitido', 'error');
        } else {
            showNotification('Mensaje inválido', 'warning');
        }
        return;
    }

    try {
        await apiRequest('/api/messages', {
            method: 'POST',
            body: JSON.stringify({
                text: messageText,
                category: messageCategory,
                parentId: parentMessage ? parentMessage.id : null,
            }),
        });

        await loadMessagesFromBackend();
        document.getElementById('messageInput').value = '';
        if (categoryInput) {
            categoryInput.value = 'general';
        }
        cancelReply();
        document.getElementById('charCount').textContent = '0';
        renderMessages();
        renderProfileSection();
        showNotification(parentMessage ? '¡Respuesta publicada con exito!' : '¡Mensaje publicado con exito!', 'success');
    } catch (error) {
        showNotification(error.message || 'No se pudo publicar el mensaje', 'error');
    }
}

// ========================================
// MENSAJES: EDITAR
// ========================================

function editMessage(messageId) {
    const message = allMessages.find(m => m.id === messageId);
    if (!message) return;

    // Validar que sea el propietario (comparación robusta)
    if (String(message.userId) !== String(currentUser.id)) {
        showNotification('No puedes editar mensajes de otros usuarios', 'error');
        return;
    }

    // Abrir modal de edición
    editingMessageId = messageId;
    document.getElementById('editMessageInput').value = message.text;
    document.getElementById('editCharCount').textContent = message.text.length;
    document.getElementById('editModal').classList.remove('hidden');
    animateModalOpen('#editModal');
}

function closeEditModal() {
    document.getElementById('editModal').classList.add('hidden');
    document.getElementById('editMessageInput').value = '';
    editingMessageId = null;
}

function saveEditedMessage(event) {
    event.preventDefault();
    
    const message = allMessages.find(m => m.id === editingMessageId);
    if (!message) return;

    // Obtener y sanitizar
    const rawText = document.getElementById('editMessageInput').value;
    const newText = sanitizeString(rawText, 500);

    // Validación con función dedicada
    if (!isValidMessage(newText)) {
        if (!newText || newText.length < 3) {
            showNotification('El mensaje debe tener entre 3 y 500 caracteres', 'warning');
        } else if (newText.length > 500) {
            showNotification('El mensaje no puede exceder 500 caracteres', 'error');
        } else if (containsMaliciousContent(newText)) {
            showNotification('El mensaje contiene contenido no permitido', 'error');
        } else {
            showNotification('Mensaje inválido', 'warning');
        }
        return;
    }

    // Validar que el mensaje realmente haya cambiado
    if (newText === message.text) {
        showNotification('No has realizado ningún cambio', 'info');
        closeEditModal();
        return;
    }

    message.text = newText;
    message.updatedAt = new Date().toISOString();
    saveToLocalStorage();
    renderMessages();
    renderProfileSection();
    closeEditModal();
    showNotification('Mensaje actualizado correctamente', 'success');
}

// ========================================
// MENSAJES: ELIMINAR
// ========================================

function deleteMessage(messageId) {
    const message = allMessages.find(m => m.id === messageId);
    if (!message) return;

    // Validar que sea el propietario (comparación robusta)
    if (String(message.userId) !== String(currentUser.id)) {
        showNotification('No puedes eliminar mensajes de otros usuarios', 'error');
        return;
    }

    allMessages = allMessages.filter(m => m.id !== messageId);
    saveToLocalStorage();
    renderMessages();
    renderProfileSection();
    showNotification('Mensaje eliminado correctamente', 'success');
}

// ========================================
// MENSAJES: RENDERIZAR
// ========================================

function renderMessages() {
    const messagesList = document.getElementById('messagesList');
    const emptyMessages = document.getElementById('emptyMessages');
    const messagesInfo = document.getElementById('messagesInfo');

    // Si el muro es privado para usuarios registrados, exigir sesión
    if (!currentUser) {
        messagesList.innerHTML = '';
        emptyMessages.classList.remove('hidden');
        emptyMessages.innerHTML = `
            <p class="text-2xl font-bold mb-2" style="color: #3d2817;">ACCESO RESTRINGIDO</p>
            <p class="text-xl" style="color: #666;">Inicia sesion para ver los mensajes del muro.</p>
        `;
        if (messagesInfo) {
            messagesInfo.textContent = 'Inicia sesion para listar mensajes';
        }
        return;
    }

    const visibleMessages = getVisibleMessages();
    const rootMessages = visibleMessages.filter(msg => !msg.parentId);
    const limitedRoots = selectedMessageLimit > 0 ? rootMessages.slice(0, selectedMessageLimit) : rootMessages;

    if (limitedRoots.length === 0) {
        messagesList.innerHTML = '';
        emptyMessages.classList.remove('hidden');
        emptyMessages.innerHTML = `
            <p class="text-2xl font-bold mb-2" style="color: #3d2817;">NO HAY MENSAJES!</p>
            <p class="text-xl" style="color: #666;">Prueba con otra categoria o publica el primero.</p>
        `;
        if (messagesInfo) {
            messagesInfo.textContent = '0 mensajes encontrados';
        }
        return;
    }

    emptyMessages.classList.add('hidden');
    messagesList.innerHTML = limitedRoots
        .map((msg, index) => createMessageHTML(msg, index, limitedRoots.length, 0, visibleMessages))
        .join('');
    animateMessageCards();

    if (messagesInfo) {
        const categoryLabel = selectedCategoryFilter === 'all'
            ? 'Todas'
            : getCategoryLabel(selectedCategoryFilter);
        const limitLabel = selectedMessageLimit > 0 ? `Ultimos ${selectedMessageLimit}` : 'Todos';
        const totalShown = limitedRoots.reduce((acc, rootMsg) => acc + countThreadNodes(rootMsg.id, visibleMessages), 0);
        messagesInfo.textContent = `Mostrando ${totalShown} | ${categoryLabel} | ${limitLabel}`;
    }
}

function createMessageHTML(msg, index, total, depth = 0, visibleMessages = []) {
    // Comparación robusta de IDs (convertir ambos a string para evitar problemas de tipos)
    const isOwner = currentUser && String(msg.userId) === String(currentUser.id);
    const timeAgo = getTimeAgo(msg.createdAt);
    const exactDate = formatDateTime(msg.createdAt);
    const isEdited = msg.updatedAt !== msg.createdAt;
    const isNewest = depth === 0 && index === 0;
    const isEven = index % 2 === 0;
    const categoryLabel = getCategoryLabel(msg.category);
    const levelInfo = getUserLevelById(msg.userId);
    const publicName = msg.authorDisplayName || msg.displayName || `@${msg.username}`;
    const avatarUrl = sanitizeAvatarUrl(msg.avatarDataUrl || '');
    
    // Debug: Mostrar comparación de IDs
    if (currentUser) {
        console.log(`🔍 Mensaje #${msg.id}: userId=${msg.userId} (${typeof msg.userId}), currentUserId=${currentUser.id} (${typeof currentUser.id}), isOwner=${isOwner}`);
    }

    const cardBackground = depth > 0
        ? 'linear-gradient(145deg, #fff8e1 0%, #ffefc4 100%)'
        : isNewest
        ? 'linear-gradient(145deg, #fff3cd 0%, #ffd166 100%)'
        : isEven
            ? 'linear-gradient(145deg, #ffe5b4 0%, #ffd89b 100%)'
            : 'linear-gradient(145deg, #e0f2ff 0%, #bde0fe 100%)';
    const cardBorder = depth > 0 ? '#7c3aed' : isNewest ? '#e65100' : isEven ? '#ff6b35' : '#4361ee';
    const sideOffset = depth === 0 && total > 1 ? (isEven ? 'md:ml-0 md:mr-10' : 'md:ml-10 md:mr-0') : '';
    const badgeText = isNewest ? 'ULTIMO MENSAJE' : `MENSAJE #${total - index}`;

    let html = `
        <article class="retro-box p-4 crt-glow ${sideOffset}" style="background: ${cardBackground}; border-left: 8px solid ${cardBorder};">
            <div class="flex justify-between items-start mb-3 flex-wrap gap-2">
                <div>
                    <p class="inline-block px-2 py-1 mb-2 text-xs border-2 border-black bg-white" style="font-family: 'Press Start 2P', cursive;">${badgeText}</p>
                    ${avatarUrl ? `<img src="${escapeHtml(avatarUrl)}" alt="Avatar" class="w-12 h-12 object-cover border-2 border-black mb-2 bg-white">` : ''}
                    <button onclick="navigateToUserProfile('${escapeHtml(msg.username)}')" class="font-bold text-2xl underline hover:no-underline" style="color: #8b4513; font-family: 'VT323', monospace;">${escapeHtml(publicName)}</button>
                    <p class="text-sm" style="color: #5f0f40; font-family: 'Press Start 2P', cursive;">NIVEL: ${escapeHtml(levelInfo.name)}</p>
                    <p class="text-lg" style="color: #666; font-family: 'VT323', monospace;">${timeAgo}</p>
                    <p class="text-base" style="color: #5f0f40; font-family: 'Press Start 2P', cursive;">CAT: ${escapeHtml(categoryLabel)}</p>
                    <p class="text-base" style="color: #666; font-family: 'VT323', monospace;">${exactDate}</p>
                </div>
    `;

    if (currentUser) {
        html += `
                <div class="flex gap-2 flex-wrap">
                    <button onclick="startReply(${msg.id})" class="retro-btn bg-purple-300 text-black px-3 py-1 text-xs hover:bg-purple-200" style="font-size: 8px;">RESPONDER</button>
                    ${isOwner ? `<button onclick="editMessage(${msg.id})" class="retro-btn bg-yellow-300 text-black px-3 py-1 text-xs hover:bg-yellow-200" style="font-size: 8px;">EDIT</button>` : ''}
                    ${isOwner ? `<button onclick="deleteMessage(${msg.id})" class="retro-btn bg-red-300 text-black px-3 py-1 text-xs hover:bg-red-200" style="font-size: 8px;">DELETE</button>` : ''}
                </div>
        `;
    }

        html += `
            </div>
            <p class="break-words mb-2 text-xl" style="color: #2c1e3f; font-family: 'VT323', monospace; line-height: 1.4;">${escapeHtml(msg.text)}</p>
    `;

    if (isEdited) {
        html += `<p class="text-lg italic" style="color: #999; font-family: 'VT323', monospace;">(EDITADO)</p>`;
    }

    if (depth < 6) {
        const replies = getRepliesForMessage(msg.id, visibleMessages);
        if (replies.length > 0) {
            html += `
                <div class="mt-3 pl-4 border-l-4 border-purple-300 space-y-3">
                    ${replies.map((replyMsg, replyIndex) => createMessageHTML(replyMsg, replyIndex, replies.length, depth + 1, visibleMessages)).join('')}
                </div>
            `;
        }
    }

    html += `</article>`;
    return html;
}

function getRepliesForMessage(parentId, visibleMessages) {
    return visibleMessages
        .filter(msg => String(msg.parentId) === String(parentId))
        .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
}

function getUserLevelById(userId) {
    const contributions = allMessages.filter(msg => String(msg.userId) === String(userId)).length;
    if (contributions >= 50) return { name: 'Leyenda', rank: 5 };
    if (contributions >= 25) return { name: 'Experto', rank: 4 };
    if (contributions >= 10) return { name: 'Avanzado', rank: 3 };
    if (contributions >= 3) return { name: 'Colaborador', rank: 2 };
    return { name: 'Nuevo', rank: 1 };
}

function countThreadNodes(rootId, visibleMessages) {
    const replies = getRepliesForMessage(rootId, visibleMessages);
    return 1 + replies.reduce((acc, replyMsg) => acc + countThreadNodes(replyMsg.id, visibleMessages), 0);
}

function startReply(messageId) {
    const message = allMessages.find(m => String(m.id) === String(messageId));
    if (!message) {
        showNotification('No se encontro el mensaje a responder.', 'error');
        return;
    }

    replyingToMessageId = message.id;
    const replyContext = document.getElementById('replyContext');
    const replyContextText = document.getElementById('replyContextText');
    const categoryInput = document.getElementById('messageCategory');
    const messageInput = document.getElementById('messageInput');

    if (replyContext) {
        replyContext.classList.remove('hidden');
    }
    if (replyContextText) {
        replyContextText.textContent = `Respondiendo a @${message.username}`;
    }
    if (categoryInput) {
        categoryInput.value = normalizeCategory(message.category || 'general');
    }
    if (messageInput) {
        messageInput.focus();
    }

    showNotification(`Respondiendo a @${message.username}`, 'info');
}

function cancelReply() {
    replyingToMessageId = null;
    const replyContext = document.getElementById('replyContext');
    if (replyContext) {
        replyContext.classList.add('hidden');
    }
}

// ========================================
// UTILIDADES Y VALIDACIONES ROBUSTAS
// ========================================

// Sanitización de strings - elimina caracteres peligrosos
function sanitizeString(str, maxLength = 500) {
    if (typeof str !== 'string') return '';
    
    // Convertir a string y hacer trim
    let sanitized = String(str).trim();
    
    // Limitar longitud
    if (sanitized.length > maxLength) {
        sanitized = sanitized.substring(0, maxLength);
    }
    
    return sanitized;
}

// Detectar caracteres sospechosos o scripts maliciosos
function containsMaliciousContent(str) {
    const dangerousPatterns = [
        /<script[^>]*>.*?<\/script>/gi,  // Scripts
        /<iframe[^>]*>.*?<\/iframe>/gi,   // Iframes
        /javascript:/gi,                   // JavaScript protocol
        /on\w+\s*=/gi,                    // Event handlers (onclick, onerror, etc)
        /<embed[^>]*>/gi,                  // Embed tags
        /<object[^>]*>/gi,                 // Object tags
        /eval\s*\(/gi,                    // eval calls
        /expression\s*\(/gi               // CSS expressions
    ];
    
    return dangerousPatterns.some(pattern => pattern.test(str));
}

// Validación de email ESTRICTA
function isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    
    // Límites de longitud razonables
    if (email.length < 5 || email.length > 254) return false;
    
    // Regex RFC 5322 simplificada pero estricta
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (!emailRegex.test(email)) return false;
    
    // Validar que tenga exactamente un @
    if ((email.match(/@/g) || []).length !== 1) return false;
    
    // Validar partes del email
    const parts = email.split('@');
    const localPart = parts[0];
    const domain = parts[1];
    
    // Local part no puede estar vacío ni ser muy largo
    if (!localPart || localPart.length > 64) return false;
    
    // Dominio debe tener al menos un punto
    if (!domain || !domain.includes('.')) return false;
    
    // TLD (después del último punto) debe tener al menos 2 caracteres
    const domainParts = domain.split('.');
    const tld = domainParts[domainParts.length - 1];
    if (!tld || tld.length < 2) return false;
    
    return true;
}

// Validación de username ESTRICTA
function isValidUsername(username) {
    if (!username || typeof username !== 'string') return false;
    
    // Longitud entre 3 y 20
    if (username.length < 3 || username.length > 20) return false;
    
    // Solo alfanuméricos, guiones y guiones bajos
    const usernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!usernameRegex.test(username)) return false;
    
    // No puede empezar con guion
    if (username.startsWith('-') || username.startsWith('_')) return false;
    
    // No puede terminar con guion
    if (username.endsWith('-') || username.endsWith('_')) return false;
    
    // No puede tener guiones consecutivos
    if (username.includes('--') || username.includes('__')) return false;
    
    // Palabras reservadas o prohibidas
    const forbiddenWords = ['admin', 'root', 'system', 'null', 'undefined', 'test'];
    const lowerUsername = username.toLowerCase();
    if (forbiddenWords.some(word => lowerUsername.includes(word))) return false;
    
    return true;
}

// Validación de contraseña ESTRICTA
function isStrongPassword(password) {
    if (!password || typeof password !== 'string') return false;
    
    // Longitud mínima 6, máxima 128
    if (password.length < 6 || password.length > 128) return false;
    
    // Debe tener al menos una letra
    const hasLetter = /[a-zA-Z]/.test(password);
    if (!hasLetter) return false;
    
    // Debe tener al menos un número
    const hasNumber = /[0-9]/.test(password);
    if (!hasNumber) return false;
    
    // No puede ser una contraseña común
    const commonPasswords = ['123456', 'password', 'qwerty', 'abc123', '111111', '123123'];
    const lowerPassword = password.toLowerCase();
    if (commonPasswords.some(common => lowerPassword.includes(common))) return false;
    
    return true;
}

// Validación de mensaje de texto
function isValidMessage(text) {
    if (!text || typeof text !== 'string') return false;
    
    const trimmed = text.trim();
    
    // Longitud entre 3 y 500
    if (trimmed.length < 3 || trimmed.length > 500) return false;
    
    // No puede contener solo espacios o caracteres especiales
    if (!/[a-zA-Z0-9]/.test(trimmed)) return false;
    
    // Detectar contenido malicioso
    if (containsMaliciousContent(trimmed)) return false;
    
    return true;
}

function normalizeCategory(category) {
    if (typeof category !== 'string') return 'general';
    const normalized = category.trim().toLowerCase();
    return ALLOWED_CATEGORIES.includes(normalized) ? normalized : 'general';
}

function getCategoryLabel(category) {
    const normalized = normalizeCategory(category);
    return CATEGORY_LABELS[normalized] || 'General';
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    if (Number.isNaN(date.getTime())) return 'Fecha no valida';
    return date.toLocaleString('es-ES', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function getVisibleMessages() {
    return allMessages.filter(msg => {
        if (selectedCategoryFilter === 'all') return true;
        return normalizeCategory(msg.category) === selectedCategoryFilter;
    });
}

function setupMessageFilters() {
    const filterCategory = document.getElementById('filterCategory');
    const messageLimit = document.getElementById('messageLimit');

    if (filterCategory) {
        selectedCategoryFilter = filterCategory.value === 'all'
            ? 'all'
            : normalizeCategory(filterCategory.value);
    }

    if (messageLimit) {
        const parsed = Number.parseInt(messageLimit.value, 10);
        selectedMessageLimit = Number.isNaN(parsed) || parsed < 0 ? 0 : parsed;
    }

    if (filterCategory) {
        filterCategory.addEventListener('change', () => {
            selectedCategoryFilter = filterCategory.value === 'all'
                ? 'all'
                : normalizeCategory(filterCategory.value);
            renderMessages();
        });
    }

    if (messageLimit) {
        messageLimit.addEventListener('change', () => {
            const parsed = Number.parseInt(messageLimit.value, 10);
            selectedMessageLimit = Number.isNaN(parsed) || parsed < 0 ? 0 : parsed;
            renderMessages();
        });
    }
}

function getTimeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;

    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (seconds < 60) return 'Hace unos segundos';
    if (minutes < 60) return `Hace ${minutes} minuto${minutes > 1 ? 's' : ''}`;
    if (hours < 24) return `Hace ${hours} hora${hours > 1 ? 's' : ''}`;
    if (days < 7) return `Hace ${days} día${days > 1 ? 's' : ''}`;

    return date.toLocaleDateString('es-ES');
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function setupMessageInputListener() {
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.addEventListener('input', () => {
            document.getElementById('charCount').textContent = messageInput.value.length;
        });
    }

    const editMessageInput = document.getElementById('editMessageInput');
    if (editMessageInput) {
        editMessageInput.addEventListener('input', () => {
            document.getElementById('editCharCount').textContent = editMessageInput.value.length;
        });
    }
}

function setupProfileListeners() {
    const avatarInput = document.getElementById('profileAvatarInput');
    if (avatarInput) {
        avatarInput.addEventListener('change', handleProfileAvatarUpload);
    }

    const coverInput = document.getElementById('profileCoverInput');
    if (coverInput) {
        coverInput.addEventListener('change', handleProfileCoverUpload);
    }
}

function toggleProfileSection() {
    navigateTo('/profile');
}

function setProfileEditingState(isEditing) {
    isProfileEditing = isEditing;

    const firstNameEl = document.getElementById('profileFirstName');
    const lastNameEl = document.getElementById('profileLastName');
    const avatarInput = document.getElementById('profileAvatarInput');
    const coverInput = document.getElementById('profileCoverInput');
    const editBtn = document.getElementById('profileEditBtn');
    const saveBtn = document.getElementById('profileSaveBtn');
    const cancelBtn = document.getElementById('profileCancelBtn');

    if (firstNameEl) firstNameEl.disabled = !isEditing;
    if (lastNameEl) lastNameEl.disabled = !isEditing;
    if (avatarInput) avatarInput.disabled = !isEditing;
    if (coverInput) coverInput.disabled = !isEditing;

    if (editBtn) {
        if (isEditing) editBtn.classList.add('hidden');
        else editBtn.classList.remove('hidden');
    }

    if (saveBtn) {
        if (isEditing) saveBtn.classList.remove('hidden');
        else saveBtn.classList.add('hidden');
    }

    if (cancelBtn) {
        if (isEditing) cancelBtn.classList.remove('hidden');
        else cancelBtn.classList.add('hidden');
    }
}

function startEditProfile() {
    if (!currentUser) {
        showNotification('Debes iniciar sesion para editar el perfil.', 'warning');
        return;
    }

    if (currentProfileUsername && !isViewingOwnProfile(currentProfileUsername)) {
        showNotification('No puedes editar el perfil de otro usuario.', 'error');
        return;
    }

    setProfileEditingState(true);
}

function cancelEditProfile() {
    if (!currentUser) return;

    const firstNameEl = document.getElementById('profileFirstName');
    const lastNameEl = document.getElementById('profileLastName');
    const avatarInput = document.getElementById('profileAvatarInput');
    const coverInput = document.getElementById('profileCoverInput');

    if (firstNameEl) firstNameEl.value = currentUser.firstName || '';
    if (lastNameEl) lastNameEl.value = currentUser.lastName || '';
    if (avatarInput) avatarInput.value = '';
    if (coverInput) coverInput.value = '';

    setProfileEditingState(false);
}

function renderProfileSection() {
    const section = document.getElementById('profileSection');
    const postsList = document.getElementById('profilePostsList');
    const postsEmpty = document.getElementById('profilePostsEmpty');
    const coverEl = document.getElementById('profileCover');
    const avatarEl = document.getElementById('profileAvatar');
    const firstNameEl = document.getElementById('profileFirstName');
    const lastNameEl = document.getElementById('profileLastName');
    const usernameEl = document.getElementById('profileUsername');
    const emailEl = document.getElementById('profileEmail');
    const levelEl = document.getElementById('profileLevelInfo');
    const editBtn = document.getElementById('profileEditBtn');
    const friendBtn = document.getElementById('profileFriendBtn');
    const followBtn = document.getElementById('profileFollowBtn');
    const twoFactorBtn = document.getElementById('profileTwoFactorBtn');
    const twoFactorStatusEl = document.getElementById('profileTwoFactorStatus');
    const friendsCountEl = document.getElementById('profileFriendsCount');
    const followersCountEl = document.getElementById('profileFollowersCount');
    const followingCountEl = document.getElementById('profileFollowingCount');
    const heroNameEl = document.getElementById('profileHeroName');
    const heroHandleEl = document.getElementById('profileHeroHandle');

    if (!section) return;

    if (!currentUser || !isProfileSectionVisible) {
        setProfileEditingState(false);
        section.classList.add('hidden');
        return;
    }

    section.classList.remove('hidden');

    const profileUser = activeProfileData || getProfileUserContext();
    if (!profileUser) {
        if (firstNameEl) firstNameEl.value = '';
        if (lastNameEl) lastNameEl.value = '';
        if (usernameEl) usernameEl.value = currentProfileUsername || 'desconocido';
        if (emailEl) emailEl.value = '';
        if (avatarEl) avatarEl.src = 'https://placehold.co/128x128/f3e8b0/3d2817?text=NO+USER';
        if (coverEl) {
            coverEl.style.backgroundImage = 'repeating-linear-gradient(45deg, #7f1d1d 0px, #7f1d1d 18px, #b91c1c 18px, #b91c1c 36px)';
            coverEl.style.backgroundSize = 'cover';
            coverEl.style.backgroundPosition = 'center';
        }
        if (levelEl) levelEl.textContent = 'Perfil no encontrado';
        if (heroNameEl) heroNameEl.textContent = 'Usuario no encontrado';
        if (heroHandleEl) heroHandleEl.textContent = '@desconocido';
        if (editBtn) editBtn.classList.add('hidden');
        if (friendBtn) friendBtn.classList.add('hidden');
        if (followBtn) followBtn.classList.add('hidden');
        if (friendsCountEl) friendsCountEl.textContent = '0';
        if (followersCountEl) followersCountEl.textContent = '0';
        if (followingCountEl) followingCountEl.textContent = '0';
        setProfileEditingState(false);
        if (postsList) {
            postsList.innerHTML = `
                <article class="p-3 bg-white border-4 border-black">
                    <p class="font-bold text-lg" style="color: #7f1d1d;">No se encontro este usuario.</p>
                </article>
            `;
        }
        if (postsEmpty) postsEmpty.classList.add('hidden');
        return;
    }

    if (firstNameEl) firstNameEl.value = profileUser.firstName || '';
    if (lastNameEl) lastNameEl.value = profileUser.lastName || '';
    if (usernameEl) usernameEl.value = profileUser.username || '';
    if (emailEl) emailEl.value = profileUser.email || '';

    const displayName = `${profileUser.firstName || ''} ${profileUser.lastName || ''}`.trim() || profileUser.username;
    if (heroNameEl) heroNameEl.textContent = displayName;
    if (heroHandleEl) heroHandleEl.textContent = `@${profileUser.username}`;

    const avatarUrl = sanitizeImageUrl(profileUser.avatarDataUrl || '');
    if (avatarEl) {
        avatarEl.src = avatarUrl || 'https://placehold.co/128x128/f3e8b0/3d2817?text=NO+FOTO';
    }

    if (coverEl) {
        const coverUrl = sanitizeImageUrl(profileUser.coverDataUrl || '');
        if (coverUrl) {
            coverEl.style.backgroundImage = `url('${coverUrl}')`;
        } else {
            coverEl.style.backgroundImage = 'repeating-linear-gradient(45deg, #ff6b35 0px, #ff6b35 18px, #ffd166 18px, #ffd166 36px)';
        }
        coverEl.style.backgroundSize = 'cover';
        coverEl.style.backgroundPosition = 'center';
    }

    const isOwnProfile = isViewingOwnProfile(profileUser.username);
    const level = profileUser.level || getUserLevelById(profileUser.id);
    const profileMessages = activeProfileMessages.length > 0 ? activeProfileMessages : getMessagesForUser(profileUser);
    const socialFromApi = profileUser.social;
    const socialFromLocal = getUserSocialMetrics(profileUser);
    const social = socialFromApi
        ? {
            friendsCount: socialFromApi.friends,
            followersCount: socialFromApi.followers,
            followingCount: socialFromApi.following,
            isFriendWithViewer: socialFromApi.viewerIsFriend,
            viewerFollowsProfile: socialFromApi.viewerFollows,
        }
        : socialFromLocal;
    if (levelEl) {
        levelEl.textContent = `Perfil: @${profileUser.username} | Nivel: ${level.name} | Publicaciones: ${profileMessages.length}`;
    }
    if (friendsCountEl) friendsCountEl.textContent = String(social.friendsCount);
    if (followersCountEl) followersCountEl.textContent = String(social.followersCount);
    if (followingCountEl) followingCountEl.textContent = String(social.followingCount);

    setProfileEditingState(isProfileEditing && isOwnProfile);
    if (editBtn) {
        if (isOwnProfile) editBtn.classList.remove('hidden');
        else editBtn.classList.add('hidden');
    }
    if (friendBtn) {
        if (isOwnProfile || !currentUser || !profileUser.id) {
            friendBtn.classList.add('hidden');
        } else {
            friendBtn.classList.remove('hidden');
            friendBtn.textContent = social.isFriendWithViewer ? 'QUITAR AMIGO' : 'AGREGAR AMIGO';
        }
    }
    if (followBtn) {
        if (isOwnProfile || !currentUser || !profileUser.id) {
            followBtn.classList.add('hidden');
        } else {
            followBtn.classList.remove('hidden');
            followBtn.textContent = social.viewerFollowsProfile ? 'DEJAR DE SEGUIR' : 'SEGUIR';
        }
    }

    if (twoFactorStatusEl) {
        twoFactorStatusEl.textContent = currentUser && currentUser.twoFactorEnabled ? '2FA activado' : '2FA desactivado';
    }
    if (twoFactorBtn) {
        if (isOwnProfile && currentUser) {
            twoFactorBtn.classList.remove('hidden');
            twoFactorBtn.textContent = currentUser.twoFactorEnabled ? 'DESACTIVAR 2FA' : 'ACTIVAR 2FA';
        } else {
            twoFactorBtn.classList.add('hidden');
        }
    }

    if (!postsList || !postsEmpty) return;

    if (profileMessages.length === 0) {
        postsList.innerHTML = '';
        postsEmpty.classList.remove('hidden');
        return;
    }

    postsEmpty.classList.add('hidden');
    postsList.innerHTML = profileMessages
        .map(msg => {
            const shortText = msg.text.length > 180 ? `${msg.text.slice(0, 180)}...` : msg.text;
            const msgAvatar = sanitizeImageUrl(msg.avatarDataUrl || profileUser.avatarDataUrl || '');
            const msgDisplayName = `${profileUser.firstName || ''} ${profileUser.lastName || ''}`.trim() || profileUser.username;
            return `
                <article class="p-3 bg-white border-4 border-black">
                    <div class="flex items-start gap-3 mb-2">
                        <img src="${escapeHtml(msgAvatar || 'https://placehold.co/64x64/f3e8b0/3d2817?text=U') }" alt="Avatar" class="w-12 h-12 border-2 border-black object-cover bg-white">
                        <div class="min-w-0">
                            <p class="font-bold text-xl leading-tight" style="color: #3d2817;">${escapeHtml(msgDisplayName)}</p>
                            <p class="text-xs" style="color: #5f0f40; font-family: 'Press Start 2P', cursive;">${escapeHtml(getCategoryLabel(msg.category))} • ${escapeHtml(formatDateTime(msg.createdAt))}</p>
                        </div>
                    </div>
                    <p class="text-lg" style="color: #2c1e3f;">${escapeHtml(shortText)}</p>
                </article>
            `;
        })
        .join('');
}

function handleProfileSave(event) {
    event.preventDefault();
    if (!currentUser) return;
    if (!isViewingOwnProfile(currentUser.username)) {
        showNotification('Solo puedes editar tu propio perfil.', 'error');
        return;
    }

    const firstNameInput = document.getElementById('profileFirstName');
    const lastNameInput = document.getElementById('profileLastName');

    const firstName = sanitizeString(firstNameInput ? firstNameInput.value : '', 50);
    const lastName = sanitizeString(lastNameInput ? lastNameInput.value : '', 50);

    if (firstName.length < 2) {
        showNotification('El nombre debe tener al menos 2 caracteres.', 'warning');
        return;
    }

    if (lastName.length < 2) {
        showNotification('Los apellidos deben tener al menos 2 caracteres.', 'warning');
        return;
    }

    if (containsMaliciousContent(firstName) || containsMaliciousContent(lastName)) {
        showNotification('Nombre o apellidos no validos.', 'error');
        return;
    }

    currentUser.firstName = firstName;
    currentUser.lastName = lastName;
    syncCurrentUserToRegistry();
    saveToLocalStorage();
    setProfileEditingState(false);
    updateUI();
    renderMessages();
    renderProfileSection();
    showNotification('Perfil actualizado.', 'success');
}

function handleProfileAvatarUpload(event) {
    if (!currentUser) return;
    if (!isViewingOwnProfile(currentUser.username)) {
        showNotification('Solo puedes editar tu propio perfil.', 'error');
        return;
    }
    if (!isProfileEditing) {
        showNotification('Pulsa EDIT PROFILE antes de cambiar la foto.', 'warning');
        return;
    }

    const file = event && event.target && event.target.files ? event.target.files[0] : null;
    if (!file) return;

    const allowedTypes = ['image/png', 'image/jpeg', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
        showNotification('Formato no permitido. Usa PNG, JPG o WEBP.', 'error');
        return;
    }

    if (file.size > 2 * 1024 * 1024) {
        showNotification('La imagen supera 2MB.', 'error');
        return;
    }

    const reader = new FileReader();
    reader.onload = () => {
        const result = typeof reader.result === 'string' ? reader.result : '';
        const safeAvatar = sanitizeImageUrl(result);
        if (!safeAvatar) {
            showNotification('No se pudo procesar la imagen.', 'error');
            return;
        }

        currentUser.avatarDataUrl = safeAvatar;
        syncCurrentUserToRegistry();
        saveToLocalStorage();
        renderMessages();
        renderProfileSection();
        showNotification('Foto de perfil actualizada.', 'success');
    };

    reader.onerror = () => {
        showNotification('Error al leer la imagen.', 'error');
    };

    reader.readAsDataURL(file);
}

function handleProfileCoverUpload(event) {
    if (!currentUser) return;
    if (!isViewingOwnProfile(currentUser.username)) {
        showNotification('Solo puedes editar tu propio perfil.', 'error');
        return;
    }
    if (!isProfileEditing) {
        showNotification('Pulsa EDIT PROFILE antes de cambiar la portada.', 'warning');
        return;
    }

    const file = event && event.target && event.target.files ? event.target.files[0] : null;
    if (!file) return;

    const allowedTypes = ['image/png', 'image/jpeg', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
        showNotification('Formato no permitido. Usa PNG, JPG o WEBP.', 'error');
        return;
    }

    if (file.size > 3 * 1024 * 1024) {
        showNotification('La portada supera 3MB.', 'error');
        return;
    }

    const reader = new FileReader();
    reader.onload = () => {
        const result = typeof reader.result === 'string' ? reader.result : '';
        const safeCover = sanitizeImageUrl(result);
        if (!safeCover) {
            showNotification('No se pudo procesar la portada.', 'error');
            return;
        }

        currentUser.coverDataUrl = safeCover;
        syncCurrentUserToRegistry();
        saveToLocalStorage();
        renderProfileSection();
        showNotification('Portada actualizada.', 'success');
    };

    reader.onerror = () => {
        showNotification('Error al leer la portada.', 'error');
    };

    reader.readAsDataURL(file);
}

async function toggleFriendshipProfile() {
    if (!currentUser || !currentProfileUsername) return;

    const isFriend = Boolean(activeProfileData && activeProfileData.social && activeProfileData.social.viewerIsFriend);
    const method = isFriend ? 'DELETE' : 'POST';

    try {
        await apiRequest(`/api/profile/${encodeURIComponent(currentProfileUsername)}/friend`, { method });
        await loadActiveProfileContext();
        renderProfileSection();
        showNotification(
            isFriend
                ? `Ya no eres amigo de @${currentProfileUsername}.`
                : `Ahora eres amigo de @${currentProfileUsername}.`,
            isFriend ? 'info' : 'success'
        );
    } catch (error) {
        showNotification(error.message || 'No se pudo actualizar la amistad.', 'error');
    }
}

async function toggleFollowProfile() {
    if (!currentUser || !currentProfileUsername) return;

    const isFollowing = Boolean(activeProfileData && activeProfileData.social && activeProfileData.social.viewerFollows);
    const method = isFollowing ? 'DELETE' : 'POST';

    try {
        await apiRequest(`/api/profile/${encodeURIComponent(currentProfileUsername)}/follow`, { method });
        await loadActiveProfileContext();
        renderProfileSection();
        showNotification(
            isFollowing
                ? `Ya no sigues a @${currentProfileUsername}.`
                : `Ahora sigues a @${currentProfileUsername}.`,
            isFollowing ? 'info' : 'success'
        );
    } catch (error) {
        showNotification(error.message || 'No se pudo actualizar seguimiento.', 'error');
    }
}

function syncCurrentUserToRegistry() {
    if (!currentUser) return;
    const index = registeredUsers.findIndex(user => String(user.id) === String(currentUser.id));
    if (index === -1) return;

    registeredUsers[index] = ensureSocialFields({
        ...registeredUsers[index],
        firstName: currentUser.firstName || '',
        lastName: currentUser.lastName || '',
        avatarDataUrl: currentUser.avatarDataUrl || '',
        coverDataUrl: currentUser.coverDataUrl || '',
        friendIds: currentUser.friendIds || [],
        followingIds: currentUser.followingIds || []
    });
}

function getCurrentUserMessages() {
    if (!currentUser) return [];
    return allMessages
        .filter(msg => String(msg.userId) === String(currentUser.id))
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function isViewingOwnProfile(profileUsername) {
    if (!currentUser) return false;
    return String(currentUser.username).toLowerCase() === String(profileUsername || '').toLowerCase();
}

function getRegisteredUserById(userId) {
    return registeredUsers.find(user => Number(user.id) === Number(userId));
}

function getRegisteredUserByUsername(username) {
    return registeredUsers.find(
        user => String(user.username).toLowerCase() === String(username || '').toLowerCase()
    );
}

function getUserSocialMetrics(profileUser) {
    const profileRegistryUser = getRegisteredUserById(profileUser.id) || ensureSocialFields(profileUser);
    const viewerRegistryUser = currentUser ? getRegisteredUserById(currentUser.id) : null;

    const friendsCount = normalizeIdList(profileRegistryUser.friendIds).length;
    const followingCount = normalizeIdList(profileRegistryUser.followingIds).length;
    const followersCount = registeredUsers.filter(user => normalizeIdList(user.followingIds).includes(profileRegistryUser.id)).length;
    const isFriendWithViewer = Boolean(viewerRegistryUser && normalizeIdList(viewerRegistryUser.friendIds).includes(profileRegistryUser.id));
    const viewerFollowsProfile = Boolean(viewerRegistryUser && normalizeIdList(viewerRegistryUser.followingIds).includes(profileRegistryUser.id));

    return {
        friendsCount,
        followersCount,
        followingCount,
        isFriendWithViewer,
        viewerFollowsProfile
    };
}

function getProfileUserContext() {
    if (!currentUser) return null;

    if (!currentProfileUsername) {
        return ensureSocialFields(currentUser);
    }

    const fromRegistry = getRegisteredUserByUsername(currentProfileUsername);

    if (fromRegistry) {
        return ensureSocialFields({
            ...fromRegistry,
            firstName: sanitizeString(fromRegistry.firstName || '', 50),
            lastName: sanitizeString(fromRegistry.lastName || '', 50),
            avatarDataUrl: sanitizeImageUrl(fromRegistry.avatarDataUrl || ''),
            coverDataUrl: sanitizeImageUrl(fromRegistry.coverDataUrl || '')
        });
    }

    const fromMessages = allMessages.find(
        msg => String(msg.username).toLowerCase() === String(currentProfileUsername).toLowerCase()
    );

    if (!fromMessages) {
        return null;
    }

    return ensureSocialFields({
        id: fromMessages.userId,
        username: sanitizeString(fromMessages.username || '', 20),
        email: '',
        firstName: sanitizeString(fromMessages.firstName || '', 50),
        lastName: sanitizeString(fromMessages.lastName || '', 50),
        avatarDataUrl: sanitizeImageUrl(fromMessages.avatarDataUrl || ''),
        coverDataUrl: ''
    });
}

function getMessagesForUser(profileUser) {
    if (!profileUser) return [];
    return allMessages
        .filter(msg => String(msg.username).toLowerCase() === String(profileUser.username).toLowerCase())
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function sanitizeAvatarUrl(value) {
    return sanitizeImageUrl(value);
}

// ========================================
// NOTIFICACIONES
// ========================================

function showNotification(message, type = 'info') {
    const config = {
        text: message,
        duration: 3000,
        gravity: 'top',
        position: 'center',
        stopOnFocus: true,
        style: {
            fontFamily: "'Press Start 2P', cursive",
            fontSize: '10px',
            padding: '15px 20px',
            border: '4px solid #000',
            boxShadow: '6px 6px 0px #000'
        }
    };

    if (type === 'success') {
        config.style.background = '#86efac';
        config.style.color = '#000';
    } else if (type === 'error') {
        config.style.background = '#fca5a5';
        config.style.color = '#000';
    } else if (type === 'warning') {
        config.style.background = '#fcd34d';
        config.style.color = '#000';
    } else {
        config.style.background = '#93c5fd';
        config.style.color = '#000';
    }

    Toastify(config).showToast();
}

// ========================================
// UI: ACTUALIZAR SEGÚN ESTADO
// ========================================

function updateUI() {
    const btnLogin = document.getElementById('btnLogin');
    const btnRegister = document.getElementById('btnRegister');
    const btnProfile = document.getElementById('btnProfile');
    const btnLogout = document.getElementById('btnLogout');
    const welcomeUsername = document.getElementById('welcomeUsername');

    if (currentUser) {
        btnLogin.classList.add('hidden');
        btnRegister.classList.add('hidden');
        btnProfile.classList.remove('hidden');
        btnLogout.classList.remove('hidden');
        const displayName = `${currentUser.firstName || ''} ${currentUser.lastName || ''}`.trim();
        welcomeUsername.textContent = displayName || currentUser.username;
    } else {
        btnLogin.classList.remove('hidden');
        btnRegister.classList.remove('hidden');
        btnProfile.classList.add('hidden');
        btnLogout.classList.add('hidden');
        isProfileSectionVisible = false;
        setProfileEditingState(false);
    }

    renderRoute();
}

// ========================================
// LOCAL STORAGE
// ========================================

function saveToLocalStorage() {
    localStorage.removeItem('foroUser');
    localStorage.setItem('foroMessages', JSON.stringify(allMessages));
    localStorage.setItem('foroRegisteredUsers', JSON.stringify(registeredUsers));
}

function loadFromLocalStorage() {
    const userStr = null;
    const messagesStr = localStorage.getItem('foroMessages');
    const registeredUsersStr = localStorage.getItem('foroRegisteredUsers');

    // Cargar usuarios registrados PRIMERO
    if (registeredUsersStr) {
        try {
            const users = JSON.parse(registeredUsersStr);
            
            if (Array.isArray(users)) {
                registeredUsers = users.filter(u => {
                    return u && 
                           typeof u === 'object' && 
                           u.id && 
                           u.username && 
                           u.email &&
                           (u.password || u.authProvider === 'google');
                }).map(u => ({
                    ...ensureSocialFields(u),
                    firstName: sanitizeString(u.firstName || '', 50),
                    lastName: sanitizeString(u.lastName || '', 50)
                }));
            } else {
                registeredUsers = [];
            }
        } catch (e) {
            console.error('Error cargando usuarios registrados:', e);
            registeredUsers = [];
            localStorage.removeItem('foroRegisteredUsers');
        }
    }

    // Cargar usuario actual (sesión)
    if (userStr) {
        try {
            const user = JSON.parse(userStr);
            
            // Validar estructura del usuario
            if (user && typeof user === 'object' && user.id && user.username) {
                // Sanitizar datos del usuario al cargar
                currentUser = ensureSocialFields({
                    id: user.id,
                    username: sanitizeString(user.username, 20),
                    email: user.email ? sanitizeString(user.email, 254) : '',
                    firstName: sanitizeString(user.firstName || '', 50),
                    lastName: sanitizeString(user.lastName || '', 50),
                    avatarDataUrl: sanitizeImageUrl(user.avatarDataUrl || ''),
                    coverDataUrl: sanitizeImageUrl(user.coverDataUrl || ''),
                    friendIds: normalizeIdList(user.friendIds),
                    followingIds: normalizeIdList(user.followingIds),
                    loginAt: user.loginAt,
                    registeredAt: user.registeredAt
                });
            } else {
                currentUser = null;
            }
        } catch (e) {
            console.error('Error cargando usuario:', e);
            currentUser = null;
            localStorage.removeItem('foroUser');
        }
    }
    currentUser = null;

    // Cargar mensajes
    if (messagesStr) {
        try {
            const messages = JSON.parse(messagesStr);
            
            // Validar que sea un array
            if (Array.isArray(messages)) {
                // Filtrar y validar cada mensaje
                allMessages = messages.filter(msg => {
                    return msg && 
                           typeof msg === 'object' && 
                           msg.id && 
                           msg.userId && 
                           msg.username && 
                           msg.text &&
                           msg.createdAt;
                }).map(msg => ({
                    // Sanitizar cada mensaje al cargar
                    id: msg.id,
                    userId: msg.userId,
                    parentId: msg.parentId || null,
                    username: sanitizeString(msg.username, 20),
                    firstName: sanitizeString(msg.firstName || '', 50),
                    lastName: sanitizeString(msg.lastName || '', 50),
                    avatarDataUrl: sanitizeAvatarUrl(msg.avatarDataUrl || ''),
                    authorDisplayName: sanitizeString(msg.authorDisplayName || '', 120),
                    category: normalizeCategory(msg.category || 'general'),
                    text: sanitizeString(msg.text, 500),
                    createdAt: msg.createdAt,
                    updatedAt: msg.updatedAt || msg.createdAt
                }));
            } else {
                allMessages = [];
            }
        } catch (e) {
            console.error('Error cargando mensajes:', e);
            allMessages = [];
            localStorage.removeItem('foroMessages');
        }
    }
}

// Función auxiliar para limpiar todos los datos (útil para empezar de cero)
// Ejecutar desde consola: window.limpiarForoCompleto()
window.limpiarForoCompleto = function() {
    if (confirm('⚠️ Esto eliminará TODOS los datos (usuarios, mensajes, sesión). ¿Continuar?')) {
        localStorage.removeItem('foroUser');
        localStorage.removeItem('foroMessages');
        localStorage.removeItem('foroRegisteredUsers');
        location.reload();
        console.log('✅ Datos eliminados. Página recargada.');
    }
};

// Función para ver el estado actual (debugging)
window.verEstadoForo = function() {
    console.log('📊 ESTADO ACTUAL DEL FORO');
    console.log('═══════════════════════════');
    console.log('Usuario actual:', currentUser);
    console.log('Usuarios registrados:', registeredUsers);
    console.log('Mensajes:', allMessages);
    console.log('═══════════════════════════');
    return {
        currentUser,
        registeredUsers,
        allMessages
    };
};