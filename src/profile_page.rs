use axum::response::Html;

pub async fn page() -> Html<String> {
    crate::ui::render(
        "Mon profil",
        "/account/profile",
        r####"<div class="page-heading"><div class="eyebrow">Espace personnel</div><h1>Mon profil</h1><p class="lead">Personnalisez votre identité. Les applications ne reçoivent les informations de profil que si vous les autorisez.</p></div>
<div class="columns">
<section class="panel">
<h2>Photo de profil</h2>
<div class="avatar-editor-row"><div id="avatar-fallback" class="avatar-large" aria-hidden="true">?</div><img id="avatar-preview" class="avatar-large" alt="Votre photo de profil" hidden>
<div class="stack"><label for="avatar-file" class="button secondary">Choisir une photo</label><input id="avatar-file" type="file" accept="image/jpeg,image/png,image/webp" hidden><button type="button" id="avatar-delete" class="danger" hidden>Supprimer la photo</button></div></div>
<p class="hint">JPG, PNG ou WebP, 8 Mo maximum. La photo sera recadrée en carré puis hébergée par Donnarieix Auth.</p>
<hr>
<h2>Informations publiques</h2><form id="profile-form"><label>Nom affiché<input name="display_name" maxlength="64" autocomplete="nickname" placeholder="Votre nom public"></label><div class="hint">Votre identifiant et votre adresse email ne sont pas modifiables ici.</div><button type="submit">Enregistrer</button></form>
<p id="profile-status" class="status" role="status" aria-live="polite"></p><p id="profile-signin" hidden><a class="button secondary" href="/account">Se connecter</a></p>
</section>
<aside class="stack"><section class="panel"><h2>Mon identité</h2><p id="username" class="item-title">Chargement…</p><p id="email" class="muted"></p><p id="email-status" class="hint"></p></section>
<section class="panel"><h2>Confidentialité</h2><p class="muted">Consultez les applications ayant accès à vos informations et retirez un consentement.</p><a class="button secondary" href="/account/permissions">Gérer les applications</a></section></aside></div>
<dialog id="crop-dialog" aria-labelledby="crop-title"><form method="dialog" class="crop-inner"><h2 id="crop-title">Recadrer la photo</h2><p class="muted">Déplacez l'image avec la souris ou le doigt, puis ajustez le zoom.</p>
<div class="crop-viewport" id="crop-viewport"><img id="crop-image" alt="Image à recadrer" draggable="false"></div>
<label>Zoom <input type="range" id="crop-zoom" min="1" max="4" step="0.01" value="1"></label>
<div class="crop-actions"><button type="button" class="secondary" id="crop-reset">Réinitialiser</button><button type="button" class="secondary" id="crop-cancel">Annuler</button><button type="button" id="crop-save">Enregistrer la photo</button></div></form></dialog>
<script src="/assets/account-profile.js" defer></script>"####,
    )
}
