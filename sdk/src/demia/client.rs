use crate::{
    client::{
        Client, Result,
    }, 
    types::{block::Block, TryFromDto}
};

use super::types::{TagId, TaggedResponse};

impl Client {
    /// Finds a list of blocks by their TagId. Returns a list of blocks containing the tagId.
    /// GET /api/core/v2/tagged/{tagId}
    pub async fn get_blocks_by_tag(&self, tag: &TagId) -> Result<Vec<Block>> {
        let path = &format!("api/core/v2/tagged/{}", tag.to_string());
        let resp = self
            .node_manager
            .read()
            .await
            .get_request::<TaggedResponse>(path, None, self.get_timeout().await, false, true)
            .await?;

        let mut tagged = Vec::new();
        for block in resp.inner() {
            tagged.push(Block::try_from_dto_with_params(
                block.clone(),
                self.get_protocol_parameters().await?,
            )?)
        }

        Ok(tagged)
    }
}