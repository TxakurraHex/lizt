use crate::cpe::{CpeSource, SystemCpe};

pub trait Source {
    fn name(&self) -> &str;
    fn collect(&self) -> Vec<SystemCpe>;
}

pub struct Inventory {
    pub sources: Vec<Box<dyn Source>>,
    pub items: Vec<SystemCpe>,
}

impl Inventory {
    pub fn new(sources: Vec<Box<dyn Source>>) -> Self {
        Self {
            sources,
            items: Vec::new(),
        }
    }

    pub fn collect(&mut self) {
        for source in &self.sources {
            self.items.extend(source.collect());
        }
    }

    pub fn filter_by_source(&self, source: &CpeSource) -> Vec<&SystemCpe> {
        self.items.iter().filter(|i| &i.source == source).collect()
    }
}
