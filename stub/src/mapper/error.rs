use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum MapperError {
    InvalidArchitectureError,
    ImportedModuleError,
    ImportedFunctionError,
}

impl Error for MapperError {}

impl Display for MapperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            _ => write!(f, "{:?}", self),
        }
    }
}
