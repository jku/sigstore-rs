// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Models for interfacing with Fulcio.
//!
//! https://github.com/sigstore/fulcio/blob/9da27be4fb64b85c907ab9ddd8a5d3cbd38041d4/fulcio.proto

use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};
use pem::Pem;
use pkcs8::der::EncodePem;
use serde::{Deserialize, Serialize, Serializer};
use serde_repr::Deserialize_repr;
use x509_cert::Certificate;

fn serialize_x509_csr<S>(
    input: &x509_cert::request::CertReq,
    ser: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encoded = input
        .to_pem(pkcs8::LineEnding::CRLF)
        .map_err(serde::ser::Error::custom)?;
    let encoded = BASE64_STD_ENGINE.encode(encoded);

    ser.serialize_str(&encoded)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSigningCertificateRequest {
    #[serde(serialize_with = "serialize_x509_csr")]
    pub certificate_signing_request: x509_cert::request::CertReq,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SigningCertificate {
    SignedCertificateDetachedSct(SigningCertificateDetachedSCT),
    SignedCertificateEmbeddedSct(SigningCertificateEmbeddedSCT),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificateDetachedSCT {
    pub chain: CertificateChain,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificateEmbeddedSCT {
    pub chain: CertificateChain,
}

#[derive(Deserialize)]
pub struct CertificateChain {
    pub certificates: Vec<Pem>,
}

#[derive(Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub enum SCTVersion {
    V1 = 0,
}

pub struct CertificateResponse {
    pub cert: Certificate,
    pub chain: Vec<Certificate>,
    // pub sct: InnerDetachedSCT,
}
