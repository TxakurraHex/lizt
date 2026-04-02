use anyhow::Result;
use sqlx::PgPool;
use tokio::io::unix::AsyncFd;

use crate::loader::LoadedProbe;

// MUST MATCH SAME OBJECT IN ebpf_programs/src/main.rs
// Layout: pid(4) + tgid(4) + comm(16) = offset 24, then cve_symbol_id(8) with no padding.
#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
    pub cve_symbol_id: i64,
}

pub async fn observe(probes: Vec<LoadedProbe>, pool: &PgPool) -> Result<()> {
    let handles: Vec<_> = probes
        .into_iter()
        .map(|probe| {
            let pool = pool.clone();
            tokio::spawn(async move { poll_probe(probe, &pool).await })
        })
        .collect();

    for handle in handles {
        // Not a typo - there's actually two await unwraps.
        // Outer ? unwraps the JoinError (if the task panics or was cancelled)
        // Inner ? unwraps the Result<()> from poll_probe
        handle.await??;
    }
    Ok(())
}

async fn poll_probe(probe: LoadedProbe, pool: &PgPool) -> Result<()> {
    let LoadedProbe { _ebpf, ring_buf } = probe;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    loop {
        let mut guard = async_fd.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();

        while let Some(item) = ring_buf.next() {
            if item.len() < size_of::<Event>() {
                continue;
            }
            let event = unsafe { &*(item.as_ptr() as *const Event) };
            let process_name = comm_to_string(&event.comm);

            sqlx::query(
                r#"
                INSERT INTO symbol_observations (cve_symbol_id, pid, process_name)
                VALUES ($1, $2, $3)
                ON CONFLICT (cve_symbol_id, pid)
                DO UPDATE SET
                    call_count   = symbol_observations.call_count + 1,
                    observed_at  = NOW(),
                    process_name = EXCLUDED.process_name
                "#,
            )
            .bind(event.cve_symbol_id)
            .bind(event.pid as i32)
            .bind(&process_name)
            .execute(pool)
            .await?;
        }

        guard.clear_ready();
    }
}

fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..end]).to_string()
}
