use std::ops::{Deref, DerefMut};

use rustc_serialize::base64::{FromBase64, ToBase64};

use serde;
use serde::de::Error;

use sodiumoxide::crypto::sign;

use UNPADDED_BASE64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Base64Signature(sign::Signature);

impl Deref for Base64Signature {
    type Target = sign::Signature;

    fn deref(&self) -> &sign::Signature {
        &self.0
    }
}

impl DerefMut for Base64Signature {
    fn deref_mut(&mut self) -> &mut sign::Signature {
        &mut self.0
    }
}

impl From<sign::Signature> for Base64Signature {
    fn from(sig: sign::Signature) -> Base64Signature {
        Base64Signature(sig)
    }
}

impl From<Base64Signature> for sign::Signature {
    fn from(sig: Base64Signature) -> sign::Signature {
        sig.0
    }
}

impl serde::Serialize for Base64Signature {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0[..].to_base64(UNPADDED_BASE64))
    }
}

impl serde::Deserialize for Base64Signature {
    fn deserialize<D>(deserializer: &mut D) -> Result<Base64Signature, D::Error>
    where
        D: serde::Deserializer,
    {
        let de_string: String = try!(String::deserialize(deserializer));

        let sig = try!(
            de_string
                .from_base64()
                .ok()
                .and_then(|slice| sign::Signature::from_slice(&slice))
                .ok_or_else(|| D::Error::invalid_value("Invalid signature"))
        );

        Ok(Base64Signature(sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::sign;

    use serde_json;

    #[test]
    fn serialize() {
        let sig_bytes = b"_k{\x8c\xdd#h\x9b\"ejy\xed\xd6\xbd\x1a\xa9\x90\xf3\xbe\x10\x15\xbb\xa4\x08\xc4\xaas\x95\\\x95\xa0~\xda~\"\xf0\xb3\xdcd9\x03\xeb\xe7\xf3\x83\x8bd~\x94\xac\x88\x80\xe8\x82F8\x1dk\xf5rq\xa1\x02";
        let sig = sign::Signature::from_slice(sig_bytes).unwrap();
        let b64 = Base64Signature(sig);
        let serialized = serde_json::to_string(&b64).unwrap();

        assert_eq!(serialized, r#""X2t7jN0jaJsiZWp57da9GqmQ874QFbukCMSqc5VclaB+2n4i8LPcZDkD6+fzg4tkfpSsiIDogkY4HWv1cnGhAg""#);
    }

    #[test]
    fn deserialize() {
        let serialized = r#""X2t7jN0jaJsiZWp57da9GqmQ874QFbukCMSqc5VclaB+2n4i8LPcZDkD6+fzg4tkfpSsiIDogkY4HWv1cnGhAg""#;

        let sig_bytes = b"_k{\x8c\xdd#h\x9b\"ejy\xed\xd6\xbd\x1a\xa9\x90\xf3\xbe\x10\x15\xbb\xa4\x08\xc4\xaas\x95\\\x95\xa0~\xda~\"\xf0\xb3\xdcd9\x03\xeb\xe7\xf3\x83\x8bd~\x94\xac\x88\x80\xe8\x82F8\x1dk\xf5rq\xa1\x02";
        let expected_sig = Base64Signature(sign::Signature::from_slice(sig_bytes).unwrap());

        let de_sig: Base64Signature = serde_json::from_str(&serialized).unwrap();

        assert_eq!(de_sig, expected_sig);
    }
}
