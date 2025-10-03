// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Write};

use crate::result::{Error, Result};

pub(crate) fn open_output(path: Option<String>, force: bool) -> Result<Box<dyn Write>> {
    if path.is_none() {
        return Ok(Box::new(io::stdout().lock()));
    }

    if force {
        Ok(Box::new(
            File::create(path.unwrap()).map_err(Error::custom)?,
        ))
    } else {
        Ok(Box::new(
            File::create_new(path.unwrap()).map_err(Error::custom)?,
        ))
    }
}
