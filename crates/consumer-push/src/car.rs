//! CAR block extraction with the SHA-256 integrity check retained from Atrium.
use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use cid::Cid;
use iroh_car::CarReader;
use sha2::{Digest, Sha256};

pub(crate) async fn validated_blocks(data: &[u8]) -> Result<HashMap<Cid, Vec<u8>>> {
    let mut reader = CarReader::new(data)
        .await
        .context("Invalid firehose CAR header")?;
    let mut blocks = HashMap::new();
    while let Some((cid, bytes)) = reader
        .next_block()
        .await
        .context("Invalid firehose CAR block")?
    {
        // Preserve the previous reader's SHA-256 verification. Validate before
        // insertion so a later duplicate cannot hide an earlier invalid block.
        if cid.hash().code() == 0x12 && cid.hash().digest() != Sha256::digest(&bytes).as_slice() {
            bail!("Firehose CAR block does not match its SHA-256 CID");
        }
        blocks.insert(cid, bytes);
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_car::{CarHeader, CarWriter};

    fn cid_for(bytes: &[u8]) -> Cid {
        let hash = cid::multihash::Multihash::wrap(0x12, Sha256::digest(bytes).as_slice()).unwrap();
        Cid::new_v1(0x71, hash)
    }

    async fn archive(cid: Cid, blocks: &[&[u8]]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut writer = CarWriter::new(CarHeader::new_v1(vec![cid]), &mut data);
        for bytes in blocks {
            writer.write(cid, bytes).await.unwrap();
        }
        writer.finish().await.unwrap();
        data
    }

    #[tokio::test]
    async fn reads_valid_blocks_and_preserves_absent_lookup() {
        let bytes = b"record";
        let cid = cid_for(bytes);
        let blocks = validated_blocks(&archive(cid, &[bytes]).await)
            .await
            .unwrap();
        assert_eq!(blocks.get(&cid).unwrap(), bytes);
        assert!(!blocks.contains_key(&cid_for(b"missing")));
    }

    #[tokio::test]
    async fn rejects_wrong_hash_even_when_a_later_duplicate_is_valid() {
        let bytes = b"record";
        let cid = cid_for(bytes);
        assert!(validated_blocks(&archive(cid, &[b"tampered", bytes]).await)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_malformed_and_rootless_archives() {
        assert!(validated_blocks(b"not a CAR").await.is_err());
        let mut data = Vec::new();
        CarWriter::new(CarHeader::new_v1(Vec::new()), &mut data)
            .finish()
            .await
            .unwrap();
        assert!(validated_blocks(&data).await.is_err());
    }
}
