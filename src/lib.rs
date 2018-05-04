extern crate indolentjson;
#[macro_use]
extern crate serde_derive;
extern crate base64;
extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;
#[macro_use]
extern crate failure;

use serde::de::Error as DeError;
use serde::ser::Error as SeError;
use std::collections::HashMap;

use sodiumoxide::crypto::sign;

mod serialize_signature {
    use base64;
    use serde;
    use serde::Deserialize;
    use sodiumoxide::crypto::sign;

    pub fn serialize<S>(signature: &sign::Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&base64::encode_config(
            &signature[..],
            base64::STANDARD_NO_PAD,
        ))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<sign::Signature, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = try!(String::deserialize(d));

        let bytes = base64::decode_config(&s, base64::STANDARD_NO_PAD)
            .map_err(|e| serde::de::Error::custom(e))?;

        sign::Signature::from_slice(&bytes)
            .ok_or_else(|| serde::de::Error::custom("invalid signature"))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Signature(#[serde(with = "serialize_signature")] sign::Signature);


impl AsRef<sign::Signature> for Signature {
    fn as_ref(&self) -> &sign::Signature {
        &self.0
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Signatures(HashMap<String, HashMap<String, Signature>>);

impl Signatures {
    pub fn for_server_and_key(&self, server_name: &str, key_id: &str) -> Option<sign::Signature> {
        self.0
            .get(server_name)
            .and_then(|m| m.get(key_id))
            .map(|s| s.0)
    }
}

impl AsRef<HashMap<String, HashMap<String, Signature>>> for Signatures {
    fn as_ref(&self) -> &HashMap<String, HashMap<String, Signature>> {
        &self.0
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct EmbeddedSignatures {
    #[serde(default)]
    signatures: Signatures,
}

pub struct SignedJson<E> {
    inner: E,
    signatures: Signatures,
    bytes: Vec<u8>,
}

impl<E> SignedJson<E> {
    pub fn get_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn get_signatures(&self) -> &Signatures {
        &self.signatures
    }

    pub fn get_signatures_mut(&mut self) -> &mut Signatures {
        &mut self.signatures
    }

    pub fn verify(
        &self,
        server_name: &str,
        key_id: &str,
        key: &sign::PublicKey,
    ) -> Result<(), failure::Error> {
        if let Some(sig) = self.get_signatures()
            .for_server_and_key(server_name, key_id)
        {
            if sign::verify_detached(&sig, self.get_bytes(), key) {
                Ok(())
            } else {
                bail!("invalid signature")
            }
        } else {
            bail!("not signed by specified server/key_id")
        }
    }
}

impl<'a, E> SignedJson<E>
where
    E: serde::Deserialize<'a>,
{
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, serde_json::Error> {
        let inner = serde_json::from_slice(slice)?;

        // The deserialization above should catch any invalid json before we get here.
        let bytes = canonicalize(slice).map_err(|_| DeError::custom("invalid json"))?;

        let signatures: EmbeddedSignatures = serde_json::from_slice(slice)?;
        let signatures = signatures.signatures;

        Ok(SignedJson {
            inner,
            signatures,
            bytes,
        })
    }
}

impl<'a, E> SignedJson<E>
where
    E: serde::Serialize,
{
    pub fn wrap_value(inner: E) -> Result<Self, serde_json::Error> {
        let slice = serde_json::to_vec(&inner)?;

        let bytes = canonicalize(&slice).map_err(|_| SeError::custom("invalid json"))?;

        let signatures: EmbeddedSignatures = serde_json::from_slice(&slice)?;
        let signatures = signatures.signatures;

        Ok(SignedJson {
            inner,
            signatures,
            bytes,
        })
    }
}

impl<E> AsRef<E> for SignedJson<E> {
    fn as_ref(&self) -> &E {
        &self.inner
    }
}

impl<E> serde::Serialize for SignedJson<E>
where
    E: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer
    {
        let mut v: serde_json::Value = serde_json::from_slice(self.get_bytes())
            .map_err(|e| S::Error::custom(e))?;

        let s = serde_json::to_value(&self.signatures).map_err(|e| S::Error::custom(e))?;

        if let Some(object) = v.as_object_mut() {
            object.insert("signatures".into(), s);
        } else {
            return Err(S::Error::custom("inner is not an object"))
        }

        v.serialize(serializer)
    }
}

pub fn canonicalize(bytes: &[u8]) -> serde_json::Result<Vec<u8>> {
    let val: serde_json::Value = try!(serde_json::from_slice(bytes));
    encode_canonically(&val)
}

pub fn encode_canonically<S: serde::Serialize>(st: &S) -> serde_json::Result<Vec<u8>> {
    let mut val: serde_json::Value = serde_json::to_value(st)?;

    if let Some(obj) = val.as_object_mut() {
        obj.remove("signatures");
        obj.remove("unsigned");
    }

    // TODO: Assumes BTreeMap is serialized in key order
    let uncompact = try!(serde_json::to_vec(&val));

    let mut new_vec = Vec::with_capacity(uncompact.len());
    indolentjson::compact::compact(&uncompact, &mut new_vec).expect("Invalid JSON");

    Ok(new_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_signature() {
        let s = r#""hvA+XXFEkHk80pLMeIYjNkWy5Ds2ZckSrvj00NvbyFJQe3H9LuJNnu8JLZ/ffIzChs3HmhwPldO0MSmyJAYpCA""#;

        let _: Signature = serde_json::from_str(s).unwrap();
    }

    #[test]
    fn test_deserialize_signatures() {
        let s = r#"{"foo":{"test":"hvA+XXFEkHk80pLMeIYjNkWy5Ds2ZckSrvj00NvbyFJQe3H9LuJNnu8JLZ/ffIzChs3HmhwPldO0MSmyJAYpCA"}}"#;

        let _: Signatures = serde_json::from_str(s).unwrap();
    }

    #[test]
    fn test_verify_signed() {
        let b = r#"{"signatures": {"Alice": {"ed25519:zxcvb": "hvA+XXFEkHk80pLMeIYjNkWy5Ds2ZckSrvj00NvbyFJQe3H9LuJNnu8JLZ/ffIzChs3HmhwPldO0MSmyJAYpCA"}}, "my_key": "my_data"}"#;

        #[derive(Debug, Deserialize, PartialEq, Eq)]
        struct Test {
            my_key: String,
        };

        let s: SignedJson<Test> = SignedJson::from_slice(b.as_bytes()).unwrap();

        assert_eq!(s.as_ref(), &Test{ my_key: "my_data".into()});

        let k = b"qA\xeb\xc2^+(\\~P\x91(\xa4\xf4L\x1f\xeb\x07E\xae\x8b#q(\rMq\xf2\xc9\x8f\xe1\xca";
        println!("{}", k.len());
        let seed = sign::Seed::from_slice(k).unwrap();
        let (pubkey, _) = sign::keypair_from_seed(&seed);

        s.verify("Alice", "ed25519:zxcvb", &pubkey).unwrap();
    }

    #[test]
    fn test_round_trip() {
        let b = r#"{"signatures": {"Alice": {"ed25519:zxcvb": "hvA+XXFEkHk80pLMeIYjNkWy5Ds2ZckSrvj00NvbyFJQe3H9LuJNnu8JLZ/ffIzChs3HmhwPldO0MSmyJAYpCA"}}, "my_key": "my_data"}"#;

        #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
        struct Test {};

        let s: SignedJson<Test> = SignedJson::from_slice(b.as_bytes()).unwrap();
        let d = serde_json::to_string(&s).unwrap();

        let v1: serde_json::Value = serde_json::from_str(b).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&d).unwrap();

        assert_eq!(v1, v2);
    }
}
