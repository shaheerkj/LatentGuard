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

    const mfaField = document.getElementById("login-mfa-field");
    const mfaEl    = document.getElementById("login-mfa");
    let awaitingMfa = false;

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        errEl.hidden = true;
        errEl.textContent = "";
        submit.disabled = true;
        const oldLabel = submit.textContent;
        submit.textContent = "Signing in...";
        const mfaCode = awaitingMfa ? (mfaEl.value || "").trim() : "";
        try {
            await LG_AUTH.login(userEl.value, passEl.value, mfaCode);
            const next = new URLSearchParams(location.search).get("next") || "/";
            location.replace(next);
        } catch (err) {
            if (err.code === "mfa_required") {
                awaitingMfa = true;
                mfaField.hidden = false;
                mfaEl.required = true;
                mfaEl.focus();
                errEl.textContent = "Enter the 6-digit code from your authenticator app.";
                errEl.hidden = false;
                submit.disabled = false;
                submit.textContent = oldLabel;
                return;
            }
            if (err.code === "locked") {
                errEl.textContent = "Account locked after repeated failures. Try again in up to 15 minutes.";
                errEl.hidden = false;
            } else {
                errEl.textContent = err.message.includes("HTTP 401")
                    ? (awaitingMfa ? "Wrong MFA code." : "Wrong username or password.")
                    : `Login failed: ${err.message}`;
                errEl.hidden = false;
            }
            submit.disabled = false;
            submit.textContent = oldLabel;
        }
    });
})();
