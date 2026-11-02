//! Shared, responsive Donnarieix Auth layout for account, OAuth consent and
//! developer management screens. All page bodies are application-authored;
//! never interpolate unescaped user input into these HTML templates.
use axum::response::Html;

const STYLE: &str = r#"
:root{color-scheme:dark;--bg:#0b0e14;--surface:#171b24;--surface-hover:#202631;--text:#eef2f8;--muted:#a6b0c0;--line:#353d49;--accent:#eaf0f8;--accent-hover:#fff;--accent-soft:#293242;--danger:#ff9399;--shadow:0 10px 36px rgba(0,0,0,.12);--radius:16px;--focus:#8cb7ff;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;font-synthesis:none}
*{box-sizing:border-box}[hidden]{display:none!important}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font-size:15px;line-height:1.6;transition:background .15s,color .15s}
body[data-theme=light]{color-scheme:light;--bg:#f4f6f9;--surface:#fff;--surface-hover:#e9eef5;--text:#1c2532;--muted:#5a697a;--line:#dce2eb;--accent:#182b41;--accent-hover:#304560;--accent-soft:#e7edf5;--danger:#af353f;--shadow:0 6px 24px rgba(32,43,58,.045);--focus:#477fc9}
body[data-theme=contrast]{color-scheme:dark;--bg:#050608;--surface:#11151c;--surface-hover:#242b36;--text:#fff;--muted:#e0e6f1;--line:#8d9cb0;--accent:#fff;--accent-hover:#e1ebff;--accent-soft:#26364a;--danger:#ffb0b5;--shadow:none}
a{color:var(--text);text-underline-offset:3px}a:hover{color:var(--accent-hover)}button,input,select,textarea{font:inherit}button{cursor:pointer}button:disabled{opacity:.53;cursor:not-allowed}:focus-visible{outline:3px solid var(--focus);outline-offset:3px}
button,.button{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;border:1px solid transparent;background:var(--accent);color:var(--bg);border-radius:10px;padding:.74rem 1rem;font-weight:690;line-height:1.25;text-decoration:none;min-height:44px;transition:background .15s,transform .15s}
button:hover:not(:disabled),.button:hover{background:var(--accent-hover);color:var(--bg)}button:active:not(:disabled){transform:translateY(1px)}
button.secondary,.button.secondary{background:var(--surface-hover);color:var(--text);border-color:var(--line)}button.secondary:hover,.button.secondary:hover{background:var(--accent-soft);color:var(--text)}
button.danger{background:transparent;color:var(--danger);border-color:var(--line)}button.danger:hover{background:rgba(255,100,109,.08);color:var(--danger)}
input,textarea,select{background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:.72rem .84rem;min-height:44px;width:100%;transition:border .15s,box-shadow .15s}input:focus,textarea:focus,select:focus{border-color:var(--focus);box-shadow:0 0 0 3px color-mix(in srgb,var(--focus) 20%,transparent);outline:0}
textarea{resize:vertical;min-height:104px}label{display:grid;gap:.4rem;font-weight:570;font-size:.9rem}input[type=checkbox]{width:18px;height:18px;min-height:18px;accent-color:var(--focus)}label:has(input[type=checkbox]){display:flex;align-items:center}
form{display:grid;gap:1.08rem}form button{justify-self:start}p{margin:.4rem 0 1.1rem}h1,h2,h3{line-height:1.24;letter-spacing:-.028em}h1{font-size:clamp(1.7rem,3vw,2.3rem);font-weight:770;margin:0 0 .55rem}h2{font-size:1.19rem;margin:0 0 1.05rem}h3{font-size:1rem}small,.hint,.muted{color:var(--muted)}
.auth-layout{display:grid;grid-template-columns:252px minmax(0,1fr);min-height:100vh}
.sidebar{position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column;padding:24px 13px 16px;background:#0c1018;border-right:1px solid #303845;color:#e9edf5}
.sidebar a{color:#d6deea;text-decoration:none}
.brand{display:flex;align-items:center;gap:12px;padding:0 10px 27px;text-decoration:none;font-weight:760;letter-spacing:-.035em;line-height:1.15;white-space:nowrap}
.brand img{width:44px;height:44px;border-radius:10px;flex-shrink:0}
.brand small{display:block;font-weight:480;letter-spacing:0;margin-top:5px;font-size:.73rem;color:#a7b2c2}
.side-group{font-size:.71rem;font-weight:750;letter-spacing:.11em;text-transform:uppercase;color:#8391a5;padding:14px 15px 7px}
.side-nav{display:grid;gap:5px}.side-nav a{display:flex;align-items:center;gap:11px;padding:11px 13px;border-radius:10px;font-weight:550;font-size:.9rem;min-height:43px}
.side-nav a:hover{background:#222a36;color:white}.side-nav a[aria-current=page]{background:#e8edf5;color:#131922;font-weight:700}
.side-nav svg{width:19px;height:19px;stroke:currentColor;stroke-width:1.8;fill:none;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.sidebar-bottom{margin-top:auto;padding:16px 8px 4px;border-top:1px solid #2c3542}.sidebar-bottom label{font-size:.75rem;color:#a4afbe}.sidebar-bottom select{margin-top:5px;min-height:38px;background:#151c27;color:#e9eef7;border-color:#414b5b;font-size:.82rem}
.main{min-width:0}.topbar{min-height:96px;display:flex;align-items:center;border-bottom:1px solid var(--line);padding:21px clamp(18px,3vw,37px);gap:18px}
.topbar-kicker{font-size:.73rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);font-weight:750}.topbar-title{font-size:1.3rem;font-weight:720;margin:2px 0 0;letter-spacing:-.03em}

.page{max-width:1300px;margin:0 auto;padding:36px clamp(18px,3vw,38px) 60px}.page-heading{margin-bottom:28px}.eyebrow{color:var(--muted);font-size:.72rem;font-weight:730;text-transform:uppercase;letter-spacing:.12em;margin-bottom:9px}
.lead{color:var(--muted);max-width:68ch;font-size:1rem}.columns{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(250px,.8fr);gap:18px;align-items:start}.grid-two{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}
.panel,section.card{min-width:0;padding:27px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}.panel p:last-child{margin-bottom:0}
.stack{display:grid;gap:18px}.notice{padding:14px 16px;background:var(--accent-soft);border:1px solid var(--line);border-radius:11px;color:var(--text);margin:15px 0}.status{min-height:24px;font-weight:580;color:#82d8a2;margin:13px 0}.status[data-error=true]{color:var(--danger)}
.segmented{display:flex;padding:4px;background:var(--surface-hover);border-radius:11px;gap:4px;margin:0 0 22px}.segmented button{background:transparent;border:0;flex:1;color:var(--muted);padding:10px;min-height:41px}.segmented button:hover:not(:disabled){background:var(--accent-soft);color:var(--text)}.segmented button[aria-selected=true]{background:var(--accent);color:var(--bg)}
.account-links{display:flex;gap:10px;flex-wrap:wrap;margin:21px 0 0}.account-links button{font-size:.83rem;min-height:38px}.consent-actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:20px}.consent-actions form{display:block}.consent-actions button{min-width:130px}.view[hidden]{display:none!important}.item{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 0;border-bottom:1px solid var(--line)}.item:last-child{border-bottom:0}.item-title{font-weight:690}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.85rem;overflow-wrap:anywhere}.pill{display:inline-flex;font-size:.75rem;font-weight:680;padding:3px 10px;border-radius:100px;color:#a6e8c0;background:#163723}.toolbar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:14px;margin-bottom:21px}.empty{padding:29px 18px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:12px}
hr{border:0;border-top:1px solid var(--line);margin:26px 0}summary{cursor:pointer;color:var(--text);font-weight:630}details{border-top:1px solid var(--line);padding:13px 0}
.foot{padding:22px clamp(18px,3vw,38px);border-top:1px solid var(--line);color:var(--muted);font-size:.78rem;display:flex;justify-content:space-between;gap:15px;flex-wrap:wrap}
@media(max-width:980px){.auth-layout{grid-template-columns:210px minmax(0,1fr)}.columns{grid-template-columns:1fr}}
@media(max-width:690px){.auth-layout{display:block}.sidebar{height:auto;position:relative;padding:11px 13px 9px}.brand{padding:0 5px 10px}.brand img{width:38px;height:38px}.side-group{display:none}.side-nav{display:flex;overflow-x:auto;gap:5px}.side-nav a{white-space:nowrap;padding:8px 11px;font-size:.82rem;min-height:38px}.side-nav svg{width:16px;height:16px}.sidebar-bottom{display:none}.topbar{min-height:70px;padding:13px 18px}.topbar-title{font-size:1.1rem}.page{padding:24px 16px 45px}.panel{padding:20px}.grid-two{grid-template-columns:1fr}.foot{padding:20px 16px}.segmented{flex-wrap:wrap}.segmented button{flex:1 0 40%}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
"#;

const SCRIPT: &str = r#"(()=>{
const select=document.querySelector('[data-theme-picker]');
if(!select)return;
const saved=localStorage.getItem('auth-theme');
const selected=['system','light','dark','contrast'].includes(saved)?saved:'system';
select.value=selected;
const query=matchMedia('(prefers-color-scheme: dark)');
const apply=()=>{document.body.dataset.theme=select.value==='system'?(query.matches?'dark':'light'):select.value;};
select.addEventListener('change',()=>{localStorage.setItem('auth-theme',select.value);apply();});
query.addEventListener('change',apply);
apply();
})();"#;

pub fn render(title: &str, area: &str, body: &str) -> Html<String> {
    let developer = area.starts_with("/developer");
    let links: &[(&str, &str)] = if developer {
        &[("Applications", "/developer"), ("Mon profil", "/account/profile"), ("Autorisations", "/account/permissions")]
    } else {
        &[("Connexion", "/account"), ("Mon profil", "/account/profile"), ("Applications liées", "/account/permissions")]
    };
    let mut navigation = String::new();
    for (name, href) in links {
        let current = if area == *href { " aria-current=\"page\"" } else { "" };
        navigation.push_str(&format!(r#"<a href="{href}"{current}>{name}</a>"#));
    }
    // The developer and end-user identities are distinct. Their screens must
    // not imply that being signed into one grants access to the other.
    let section = if developer { "Développement" } else { "Identité" };
    let other = if developer { "/account" } else { "/developer" };
    let other_label = if developer { "Espace personnel" } else { "Espace développeur" };
    Html(format!(
        r####"<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta name="theme-color" content="#0b0e14"><title>{title} · Donnarieix Auth</title><link rel="icon" href="/assets/donnarieix-logo.svg" type="image/svg+xml"><style>{STYLE}</style></head><body>
<div class="auth-layout"><aside class="sidebar"><a class="brand" href="/account"><img src="/assets/donnarieix-logo.svg" width="44" height="44" alt=""><span>Donnarieix Auth<small>Identité et accès</small></span></a><div class="side-group">{section}</div><nav class="side-nav" aria-label="Navigation principale">{navigation}</nav><div class="side-group">Autre espace</div><nav class="side-nav" aria-label="Navigation secondaire"><a href="{other}">{other_label}</a></nav><div class="sidebar-bottom"><label for="theme-picker">Apparence</label><select id="theme-picker" data-theme-picker aria-label="Choisir le thème"><option value="system">Système</option><option value="dark">Sombre</option><option value="light">Clair</option><option value="contrast">Contraste élevé</option></select></div></aside>
<div class="main"><header class="topbar"><div><div class="topbar-kicker">{section}</div><div class="topbar-title">{title}</div></div></header><main class="page">{body}</main><footer class="foot"><span>Donnarieix Auth · Identité sous votre contrôle</span><span>Connexion et administration séparées</span></footer></div></div><script>{SCRIPT}</script></body></html>"####
    ))
}
