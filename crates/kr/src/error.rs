#[derive(Debug)]
pub enum KurapikaError {
    EncryptionFailure,
    DecryptionFailure,
    GenerateKeyFailure,
    GetKeyFailure,
    SignFailure,
    SignVerifyFailure,
    VerifyFailure,
    ParseFailure,
}
