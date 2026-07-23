use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum MapperError {
    InvalidArchitecture,
    ImportedModule,
    ImportedFunction,
}

impl Error for MapperError {}

impl Display for MapperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
