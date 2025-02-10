use std::collections::HashSet;
use tracing::{instrument, Level};

type Level_ = Level;

#[instrument(level = Level::TRACE, ret())]
pub(super) fn intersection(id_sets: &[HashSet<String>]) -> HashSet<String> {
    if let Some(first) = id_sets.first() {
        // intersection of all sets
        return first
            .iter()
            .filter(|elem| id_sets.iter().all(|set| set.contains(*elem)))
            .map(|elem| elem.to_owned())
            .collect::<HashSet<String>>();
    }

    HashSet::new()
}
