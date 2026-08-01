// src/xrefs.rs - full inbound function xref index.
//
// Unlike callgraph.rs, this is not a sampled navigation skeleton. It streams
// every xref whose target is a discovered function entry into one TSV file, so
// large binaries do not create tens of thousands of tiny xref files.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::Result;
use idalib::IDB;

use crate::func_discover::DiscoveredFunc;
use crate::names::render_symbol_name;

/// Export inbound references to function entry addresses as `xrefs.tsv`.
pub fn export_function_xrefs(idb: &IDB, funcs: &[DiscoveredFunc], out_dir: &Path) -> Result<usize> {
    let path = out_dir.join("xrefs.tsv");
    let mut w = BufWriter::new(File::create(&path)?);

    writeln!(w, "# Full inbound references to function entry addresses")?;
    writeln!(
        w,
        "# Format: target_addr\ttarget_name\tfrom_addr\tref_type\tcaller_func_addr\tcaller_func_name"
    )?;
    writeln!(w, "#{}", "=".repeat(80))?;

    let func_names: HashMap<u64, &str> = funcs
        .iter()
        .map(|f| (f.start_ea, f.name.as_str()))
        .collect();

    let mut count = 0usize;
    for (_id, seg) in idb.segments() {
        let mut ea = u64::from(seg.start_address());
        let end = u64::from(seg.end_address());

        while ea < end {
            let mut opt = idb.first_xref_from(ea.into(), idalib::xref::XRefQuery::ALL);
            while let Some(xr) = opt {
                let target = u64::from(xr.to());
                if let Some(target_name) = func_names.get(&target) {
                    let (caller_addr, caller_name) = caller_info(idb, &func_names, ea);
                    writeln!(
                        w,
                        "{:X}\t{}\t{:X}\t{}\t{}\t{}",
                        target,
                        tsv_field(target_name),
                        ea,
                        if xr.is_code() { "code" } else { "data" },
                        caller_addr,
                        tsv_field(&caller_name)
                    )?;
                    count += 1;
                }
                opt = xr.next_from();
            }

            match idb.next_head_with(ea.into(), end.into()) {
                Some(next) if u64::from(next) > ea => ea = u64::from(next),
                _ => break,
            }
        }
    }

    w.flush()?;
    Ok(count)
}

fn caller_info(idb: &IDB, func_names: &HashMap<u64, &str>, from_ea: u64) -> (String, String) {
    if let Some(func) = idb.function_at(from_ea.into()) {
        let start = u64::from(func.start_address());
        let name = func_names
            .get(&start)
            .map(|s| (*s).to_string())
            .or_else(|| func.name().map(|name| render_symbol_name(&name)))
            .unwrap_or_else(|| format!("sub_{:X}", start));
        return (format!("{:X}", start), name);
    }
    (String::new(), "unknown".to_string())
}

fn tsv_field(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}
