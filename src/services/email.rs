//! Mail is never logged. SMTP must use authenticated TLS; no plaintext fallback.
use std::{sync::Arc, time::Duration};

use lettre::{
    Message, SmtpTransport, Transport, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use tokio::task;

#[derive(Clone)]
pub enum Mailer {
    Disabled,
    Smtp {
        transport: Arc<SmtpTransport>,
        from: Mailbox,
    },
    #[cfg(test)]
    Test(tokio::sync::mpsc::UnboundedSender<Mail>),
}

#[derive(Clone)]
pub struct Mail {
    pub recipient: String,
    pub subject: String,
    pub body: String,
}

impl Mailer {
    pub fn from_env() -> Self {
        let host = match std::env::var("SMTP_HOST") {
            Ok(host) if !host.is_empty() => host,
            _ => return Self::Disabled,
        };
        let user =
            std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME required when SMTP_HOST set");
        let pass =
            std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD required when SMTP_HOST set");
        let from = std::env::var("MAIL_FROM")
            .expect("MAIL_FROM required when SMTP_HOST set")
            .parse::<Mailbox>()
            .expect("Invalid MAIL_FROM address");
        let transport = SmtpTransport::relay(&host)
            .expect("SMTP_HOST must be a TLS-capable relay host")
            .credentials(Credentials::new(user, pass))
            .timeout(Some(Duration::from_secs(15)))
            .build();
        Self::Smtp {
            transport: Arc::new(transport),
            from,
        }
    }

    pub fn enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub async fn send(&self, mail: Mail) -> Result<(), ()> {
        match self {
            Self::Disabled => Err(()),
            Self::Smtp { transport, from } => {
                let transport = transport.clone();
                let from = from.clone();
                task::spawn_blocking(move || {
                    let message = Message::builder()
                        .from(from)
                        .to(mail.recipient.parse::<Mailbox>().map_err(|_| ())?)
                        .subject(mail.subject)
                        .body(mail.body)
                        .map_err(|_| ())?;
                    transport.send(&message).map_err(|_| ())?;
                    Ok(())
                })
                .await
                .map_err(|_| ())?
            }
            #[cfg(test)]
            Self::Test(tx) => tx.send(mail).map_err(|_| ()),
        }
    }
}
