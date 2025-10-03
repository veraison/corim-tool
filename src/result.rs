// SPDX-License-Identifier: Apache-2.0

#[derive(Debug)]
pub enum Error {
    MissingField(String, String),
    Custom(String),
}

impl Error {
    pub fn missing_field<D: std::fmt::Display>(obj: D, field: D) -> Self {
        Self::MissingField(obj.to_string(), field.to_string())
    }

    pub fn custom<D: std::fmt::Display>(value: D) -> Self {
        Self::Custom(value.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let out;
        f.write_str(match self {
            Error::MissingField(obj, field) => {
                out = format!("missing field {}.{}", obj, field);
                out.as_str()
            }
            Error::Custom(s) => s.as_str(),
        })
    }
}

impl std::error::Error for Error {}

impl From<corim_rs::error::CorimError> for Error {
    fn from(value: corim_rs::error::CorimError) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Custom(value.to_string())
    }
}

pub trait ExitCode {
    fn exit_code(&self) -> i32;
}

pub type Result<T> = std::result::Result<T, Error>;

impl<T> ExitCode for Result<T> {
    fn exit_code(&self) -> i32 {
        match self {
            Ok(_) => 0,
            Err(_) => 2,
        }
    }
}
