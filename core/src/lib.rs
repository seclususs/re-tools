#![allow(unsafe_op_in_unsafe_fn)]

pub mod c_api;
pub mod logic;
pub mod utils;

#[cfg(feature = "python-bindings")]
pub mod python_api;

extern crate capstone;
extern crate encoding_rs;
extern crate goblin;
extern crate libc;
extern crate memchr;
extern crate petgraph;
extern crate regex;
extern crate serde;
extern crate serde_json;