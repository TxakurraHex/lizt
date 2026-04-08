use crate::finding_summary::FindingSummary;

pub fn to_json(findings: &[FindingSummary]) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec_pretty(findings)
}

pub fn to_csv(findings: &[FindingSummary]) -> Result<Vec<u8>, csv::Error> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    for f in findings {
        wtr.serialize(f)?;
    }
    wtr.into_inner()
        .map_err(|e| csv::Error::from(e.into_error()))
}
