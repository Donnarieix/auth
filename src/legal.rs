//! Public legal pages. Publication identity is configured outside version control.
//! Editorial review and final mandatory fields are required before going live.
use axum::response::Html;

fn legal_page(title: &str, route: &str, content: &str) -> Html<String> {
    crate::ui::render(title, route, content)
}
pub async fn notices() -> Html<String> {
    legal_page("Mentions légales", "/mentions-legales", r#"<article class="legal-article">
<div class="eyebrow">Informations légales</div><h1>Mentions légales</h1>
<section><h2>Édition du service</h2><p>Donnarieix Auth est un service d'identité et d'authentification proposé gratuitement et à titre non professionnel par une personne physique, sous le nom de projet Donnarieix. Donnarieix est une identité de projet, pas une société déclarée.</p>
<p>L'identification légale complète de l'éditeur, les coordonnées postales et, le cas échéant, le responsable de publication doivent être renseignés et validés avant toute ouverture publique.</p></section>
<section><h2>Infrastructure</h2><p>Le service est auto-hébergé sur une infrastructure privée administrée par l'éditeur en France. o2switch fournit des services de DNS et de messagerie, mais n'héberge pas l'application elle-même.</p></section>
<section><h2>Contact</h2><p>Pour contacter l'éditeur ou effectuer une demande relative aux données personnelles : <a href="mailto:auth@donnarieix.fr">auth@donnarieix.fr</a>.</p></section>
<section><h2>Code et contenus</h2><p>Le code du projet est consultable sur <a href="https://github.com/Donnarieix/auth" rel="noopener noreferrer">GitHub</a>. Les droits et licences applicables aux composants et contenus demeurent réservés à leurs titulaires.</p></section></article>"#)
}
pub async fn privacy() -> Html<String> {
    legal_page("Politique de confidentialité", "/confidentialite", r#"<article class="legal-article"><div class="eyebrow">Protection des données</div><h1>Politique de confidentialité</h1>
<section><h2>Responsable et contact</h2><p>Le service Donnarieix Auth est proposé par une personne physique à titre non professionnel. L'identité légale complète de l'éditeur doit être validée avant la diffusion publique. Contact : <a href="mailto:auth@donnarieix.fr">auth@donnarieix.fr</a>.</p></section>
<section><h2>Données traitées</h2><p>Les comptes comprennent un identifiant, une adresse email, le nom affiché et, éventuellement, un avatar. Les mots de passe sont conservés sous forme d'empreintes ; des données de vérification email, sessions, consentements OIDC, données de sécurité et événements administratifs sont également traités. Les applications autorisées peuvent recevoir les informations couvertes par les permissions consenties.</p></section>
<section><h2>Finalités et bases légales</h2><p>Ces données permettent la création des comptes, l'authentification, la récupération de l'accès, l'autorisation des applications et la protection contre les abus. Selon le traitement, les bases susceptibles de s'appliquer sont l'exécution du service demandé, l'intérêt légitime de sécurisation et les obligations légales. Elles doivent être documentées et confirmées avant publication.</p></section>
<section><h2>Hébergement, destinataires et durées</h2><p>La base et les avatars sont conservés sur l'infrastructure auto-hébergée en France. Le fournisseur de messagerie intervient pour l'acheminement des emails. Les données sont conservées pendant la durée nécessaire à l'usage du compte et aux obligations applicables. Les sessions et codes disposent d'expirations techniques, mais une politique complète de purge, d'audit et de sauvegardes reste à formaliser : aucune durée non implémentée n'est présentée comme garantie.</p></section>
<section><h2>Cookies et préférences</h2><p>Le service emploie des cookies de session nécessaires à l'authentification ; le choix de thème peut être conservé dans le stockage local du navigateur. Aucun traceur publicitaire ou marketing n'est intégré par cette fonctionnalité.</p></section>
<section><h2>Vos droits</h2><p>Selon les règles applicables, vous pouvez demander l'accès, la rectification, l'effacement, la limitation du traitement, l'opposition ou la portabilité en contactant <a href="mailto:auth@donnarieix.fr">auth@donnarieix.fr</a>. Vous pouvez également saisir la <a href="https://www.cnil.fr/fr/plaintes" rel="noopener noreferrer">CNIL</a>.</p></section>
<section><h2>Mises à jour</h2><p>La présente politique devra être adaptée avant l'ouverture de comptes réels ou l'ajout de nouveaux traitements et prestataires.</p></section></article>"#)
}
pub async fn terms() -> Html<String> {
    legal_page("Conditions générales d'utilisation", "/cgu", r#"<article class="legal-article"><div class="eyebrow">Conditions d'utilisation</div><h1>Conditions générales d'utilisation</h1>
<section><h2>Objet</h2><p>Donnarieix Auth propose gratuitement une identité commune pour les applications Donnarieix. L'inscription ne donne pas automatiquement accès aux fonctionnalités privées des applications clientes.</p></section>
<section><h2>Compte et sécurité</h2><p>Les utilisateurs doivent fournir des informations licites, préserver la confidentialité de leurs identifiants et ne pas tenter d'accéder à des données ou permissions qui ne leur appartiennent pas. Toute anomalie ou suspicion de compromission peut être signalée à l'éditeur.</p></section>
<section><h2>Applications connectées</h2><p>Chaque application demande les autorisations nécessaires. Une autorisation peut être retirée depuis l'espace personnel. Un retrait ne ferme pas nécessairement les sessions déjà établies dans les applications tierces ; celles-ci doivent appliquer leurs propres règles de contrôle des sessions.</p></section>
<section><h2>Disponibilité et évolution</h2><p>Le service est proposé sans garantie de fonctionnement ininterrompu. Des opérations de maintenance et des interruptions peuvent survenir. Les modalités peuvent évoluer sous réserve des règles applicables.</p></section>
<section><h2>Vie privée et contact</h2><p>Les détails des traitements figurent dans la <a href="/confidentialite">politique de confidentialité</a>. Pour toute question, écrire à <a href="mailto:auth@donnarieix.fr">auth@donnarieix.fr</a>.</p></section></article>"#)
}
pub async fn robots() -> &'static str {
    "User-agent: *\nDisallow: /\n"
}
