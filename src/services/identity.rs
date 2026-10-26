//! Conservative account identifiers for the local prototype.
//! Internationalized addresses and richer usernames require an explicit product decision.
#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    Email,
    Username,
    Password,
}

pub struct Registration {
    pub email: String,
    pub username: String,
}

pub fn normalize_email(input: &str) -> Option<String> {
    let email = input.trim();
    if email.len() > 254 || email.len() < 3 || !email.is_ascii() {
        return None;
    }
    let (local, domain) = email.split_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b))
    {
        return None;
    }
    let labels: Vec<_> = domain.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || labels.last().is_none_or(|tld| tld.len() < 2)
    {
        return None;
    }
    Some(email.to_ascii_lowercase())
}

pub fn validate_registration(
    email: &str,
    username: &str,
    password: &str,
) -> Result<Registration, ValidationError> {
    let email = normalize_email(email).ok_or(ValidationError::Email)?;
    let username = username.trim();
    if !(3..=32).contains(&username.len())
        || !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ValidationError::Username);
    }
    if !(12..=128).contains(&password.chars().count())
        || password.len() > 512
        || password.contains('\0')
    {
        return Err(ValidationError::Password);
    }
    Ok(Registration {
        email,
        username: username.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{ValidationError, normalize_email, validate_registration};

    #[test]
    fn valid_identifiers_are_normalized_without_modifying_passwords() {
        let input = validate_registration(
            "  User+tag@Example.COM ",
            " Test_user ",
            "  twelve letters long ",
        )
        .unwrap();
        assert_eq!(input.email, "user+tag@example.com");
        assert_eq!(input.username, "Test_user");
    }

    #[test]
    fn reject_ambiguous_or_unsafe_identifiers() {
        for value in [
            "a@b",
            "a@@example.com",
            "a b@example.com",
            "a..b@example.com",
            ".a@example.com",
            "a@example..com",
            "a@example.com.",
            "a@-host.com",
            "a@host-.com",
            "a@exämple.com",
        ] {
            assert_eq!(normalize_email(value), None, "{value}");
        }
        assert!(matches!(
            validate_registration("user@example.com", "../oops", "long password for me"),
            Err(ValidationError::Username)
        ));
        assert!(matches!(
            validate_registration("user@example.com", "valid", "short"),
            Err(ValidationError::Password)
        ));
    }
}
