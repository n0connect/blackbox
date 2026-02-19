#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

//! # scb-vka-common
//!
//! Common types and configuration for the vault architecture.

pub mod config;
pub mod error;
pub mod log;
pub mod util;
