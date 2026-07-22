use std::{
    error::Error,
    fmt::Display,
};

#[derive(Debug)]
pub enum MapperError {
    InvalidArchitectureError,
    ImportedModuleError,
    ImportedFunctionError,
    InitializedCellError,
    BufferAllocationError,
    TlsIndexAllocationError,
    TlsSetValueError,
    UnknownError
}

impl Error for MapperError {}

impl Display for MapperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            _ => write!(f, "{:?}", self)
        }
    }
}
