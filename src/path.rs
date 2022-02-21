use crate::{child_number::ChildNumber, error, Result};
use std::str::FromStr;

#[derive(Clone)]
pub struct Path {
    pub depth: usize,
    pub child_numbers: Vec<ChildNumber>,
}

impl FromStr for Path {
    type Err = error::Error;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let chunks = path.split('/').collect::<Vec<&str>>();
        let depth = chunks.len() - 1;

        let child_numbers = chunks
            .iter()
            .map(|&s| ChildNumber::from_str(s))
            .collect::<Result<Vec<ChildNumber>>>()
            .map_err(|_| error::Error::PathFromStr { path: path.to_string() })?;

        Ok(Self {
            depth,
            child_numbers,
        })
    }
}
