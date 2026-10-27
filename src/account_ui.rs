//! Browser conveniences for registration, email verification and recovery.
//! Protocol handlers remain JSON APIs; this view never handles raw credentials
//! server-side, and never places recovery tokens in URLs.
use axum::response::Html;

pub async fn page() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Donnarieix Auth — Account</title>
</head>
<body>
<main>
<h1>Donnarieix Auth</h1>
<p>Create and verify an account before signing in through your OIDC application.</p>
<section>
<h2>Create account</h2>
<form data-path="/register">
<label>Email <input type="email" name="email" required autocomplete="email"></label>
<label>Username <input name="username" required autocomplete="username"></label>
<label>Password <input type="password" name="password" required autocomplete="new-password"></label>
<button>Create account</button>
</form>
</section>
<section>
<h2>Verify email</h2>
<p>Check your mail. During loopback development, messages are in data/outbox.</p>
<form data-path="/email/verification/confirm">
<label>Verification code <input name="token" required autocomplete="off"></label>
<button>Verify</button>
</form>
<form data-path="/email/verification/request">
<label>Email <input type="email" name="email" required></label>
<button>Resend code</button>
</form>
</section>
<section>
<h2>Forgot password</h2>
<form data-path="/password/reset/request">
<label>Email <input type="email" name="email" required></label>
<button>Request password reset</button>
</form>
<form data-path="/password/reset/confirm">
<label>Reset code <input name="token" required autocomplete="off"></label>
<label>New password <input type="password" name="new_password" required autocomplete="new-password"></label>
<button>Reset password</button>
</form>
</section>
<p id="status" role="status" aria-live="polite"></p>
</main>
<script defer src='/assets/account.js'></script>
</body>
</html>"#,
    )
}
