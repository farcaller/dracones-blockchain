// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Aura (Authority-Round) digests
//!
//! This implements the digests for AuRa, to allow the private
//! `CompatibleDigestItem` trait to appear in public interfaces.

use crate::RAFT_ENGINE_ID;
use codec::{Codec, Encode};
use sp_consensus_slots::Slot;
use sp_runtime::generic::DigestItem;

/// A digest item which is usable with raft consensus.
pub trait CompatibleDigestItem<Signature>: Sized {
	/// Construct a digest item which contains a signature on the hash.
	fn raft_seal(signature: Signature) -> Self;

	/// If this item is an Aura seal, return the signature.
	fn as_raft_seal(&self) -> Option<Signature>;

	/// Construct a digest item which contains the slot number
	fn raft_pre_digest(slot: Slot) -> Self;

	/// If this item is an AuRa pre-digest, return the slot number
	fn as_raft_pre_digest(&self) -> Option<Slot>;
}

impl<Signature> CompatibleDigestItem<Signature> for DigestItem
where
	Signature: Codec,
{
	fn raft_seal(signature: Signature) -> Self {
		DigestItem::Seal(RAFT_ENGINE_ID, signature.encode())
	}

	fn as_raft_seal(&self) -> Option<Signature> {
		self.seal_try_to(&RAFT_ENGINE_ID)
	}

	fn raft_pre_digest(slot: Slot) -> Self {
		DigestItem::PreRuntime(RAFT_ENGINE_ID, slot.encode())
	}

	fn as_raft_pre_digest(&self) -> Option<Slot> {
		self.pre_runtime_try_to(&RAFT_ENGINE_ID)
	}
}
