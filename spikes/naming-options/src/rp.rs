//! The relying party of one test instance: its origin, its RP ID and the webauthn-rs instance.

use webauthn_rs::prelude::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder};

pub struct RelyingParty {
    pub origin: String,
    pub rp_id: String,
    /// The webauthn-rs instance, or why the library refused this origin as a relying party.
    pub webauthn: Result<Webauthn, String>,
}

impl RelyingParty {
    /// Builds the relying party for `origin`, with the origin's host as RP ID, as Vilicus does
    /// with the instance name (D51).
    pub fn from_origin(origin: &str) -> Self {
        let parsed = Url::parse(origin);
        let rp_id = parsed
            .as_ref()
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_default();
        let webauthn = parsed
            .map_err(|err| format!("invalid origin: {err}"))
            .and_then(|url| {
                WebauthnBuilder::new(&rp_id, &url)
                    .and_then(|builder| builder.rp_name("Vilicus E24 spike").build())
                    .map_err(|err| format!("webauthn-rs refused rp_id {rp_id}: {err}"))
            });
        Self {
            origin: origin.to_owned(),
            rp_id,
            webauthn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names_of_each_naming_option_are_accepted() {
        for origin in [
            "https://household.dyn.example",
            "https://household.tailnet.example",
            "https://vilicus.home.arpa",
            "https://vilicus.local",
        ] {
            let rp = RelyingParty::from_origin(origin);
            assert!(rp.webauthn.is_ok(), "{origin}: {:?}", rp.webauthn.err());
            assert_eq!(format!("https://{}", rp.rp_id), origin);
        }
    }

    #[test]
    fn an_ip_address_origin_is_refused_as_relying_party() {
        for origin in ["https://10.88.0.24", "https://[fd00:88::24]"] {
            let rp = RelyingParty::from_origin(origin);
            assert!(rp.webauthn.is_err(), "{origin} was accepted");
        }
    }
}
