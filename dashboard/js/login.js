// Login page logic. Posts credentials, stores the JWT, redirects to the
// originating path (or / by default).

(function () {
    const form     = document.getElementById("login-form");
    const userEl   = document.getElementById("login-username");
    const passEl   = document.getElementById("login-password");
    const submit   = document.getElementById("login-submit");
    const errEl    = document.getElementById("login-error");
    const warnsEl  = document.getElementById("login-warnings");

    // If we already have a fresh token, skip the form entirely.
    if (LG_AUTH.token() && !LG_AUTH.expired()) {
        const next = new URLSearchParams(location.search).get("next") || "/";
        location.replace(next);
        return;
    }

    // Surface "using default password / ephemeral secret" warnings on the
    // login page so a fresh operator can tell whether this deployment is
    // demo-grade. Public endpoint, no auth needed.
    fetch(`${LG_AUTH.API_BASE}/api/auth/config-status`)
        .then(r => r.ok ? r.json() : null)
        .then(s => {
            if (!s) return;
            const msgs = [];
            if (s.using_default_password) msgs.push("Default admin password in use. Override <code>ADMIN_PASSWORD_HASH</code> before exposing this stack.");
            if (s.using_ephemeral_secret) msgs.push("Ephemeral JWT secret. Tokens invalidate on service restart -- set <code>JWT_SECRET</code> for stability.");
            if (msgs.length) {
                warnsEl.hidden = false;
                warnsEl.innerHTML = msgs.map(m => `<div class="login-warning">${m}</div>`).join("");
            }
        })
        .catch(() => { /* config-status optional */ });

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        errEl.hidden = true;
        errEl.textContent = "";
        submit.disabled = true;
        const oldLabel = submit.textContent;
        submit.textContent = "Signing in...";
        try {
            await LG_AUTH.login(userEl.value, passEl.value);
            const next = new URLSearchParams(location.search).get("next") || "/";
            location.replace(next);
        } catch (err) {
            errEl.textContent = err.message.includes("HTTP 401")
                ? "Wrong username or password."
                : `Login failed: ${err.message}`;
            errEl.hidden = false;
            submit.disabled = false;
            submit.textContent = oldLabel;
        }
    });
})();
