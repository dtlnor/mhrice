#![recursion_limit = "2048"]

use anyhow::*;
use rayon::prelude::*;
use regex::bytes::*;
use rusoto_core::{ByteStream, Region};
use rusoto_s3::*;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor};
use std::path::*;
use std::sync::Mutex;
use structopt::*;
use walkdir::WalkDir;

mod align;
mod bitfield;
mod extract;
mod file_ext;
mod gpu;
mod mesh;
mod msg;
mod pak;
mod part_color;
mod pfb;
mod rcol;
mod rsz;
mod scn;
mod suffix;
mod tdb;
mod user;

use mesh::*;
use msg::*;
use pak::*;
use pfb::*;
use rcol::*;
use scn::*;
use tdb::*;
use user::*;

pub mod built_info {
    // The file has been placed there by the build script.
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(StructOpt)]
enum Mhrice {
    Dump {
        #[structopt(short, long)]
        pak: String,
        #[structopt(short, long)]
        name: String,
        #[structopt(short, long)]
        output: String,
    },

    DumpIndex {
        #[structopt(short, long)]
        pak: String,
        #[structopt(short, long)]
        index: u32,
        #[structopt(short, long)]
        output: String,
    },

    Scan {
        #[structopt(short, long)]
        pak: String,
    },

    GenJson {
        #[structopt(short, long)]
        pak: String,
    },

    GenWebsite {
        #[structopt(short, long)]
        pak: String,
        #[structopt(short, long)]
        output: String,
        #[structopt(long)]
        s3: Option<String>,
    },

    ReadTdb {
        #[structopt(short, long)]
        tdb: String,
    },

    ReadMsg {
        #[structopt(short, long)]
        msg: String,
    },

    ScanMsg {
        #[structopt(short, long)]
        pak: String,
        #[structopt(short, long)]
        output: String,
    },

    Grep {
        #[structopt(short, long)]
        pak: String,

        pattern: String,
    },

    SearchPath {
        #[structopt(short, long)]
        pak: String,
    },

    DumpTree {
        #[structopt(short, long)]
        pak: String,
        #[structopt(short, long)]
        list: String,
        #[structopt(short, long)]
        output: String,
    },

    ScanMesh {
        #[structopt(short, long)]
        pak: String,
    },

    ScanRcol {
        #[structopt(short, long)]
        pak: String,
    },

    DumpMesh {
        #[structopt(short, long)]
        mesh: String,
        #[structopt(short, long)]
        output: String,
    },

    DumpRcol {
        #[structopt(short, long)]
        rcol: String,
    },

    DumpMeat {
        #[structopt(short, long)]
        mesh: String,
        #[structopt(short, long)]
        rcol: String,
        #[structopt(short, long)]
        output: String,
    },

    GenMeat {
        #[structopt(short, long)]
        pak: String,
        #[structopt(short, long)]
        index: u32,
        #[structopt(short, long)]
        output: String,
    },

    GenResources {
        #[structopt(short, long)]
        pak: String,
        #[structopt(short, long)]
        output: String,
    },
}

fn dump(pak: String, name: String, output: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;
    let (index, full_path) = pak.find_file(&name).context("Cannot find subfile")?;
    println!("Full path: {}", full_path);
    println!("Index {}", index.raw());
    let content = pak.read_file(index)?;
    std::fs::write(output, content)?;
    Ok(())
}

fn dump_index(pak: String, index: u32, output: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;
    let content = pak.read_file_at(index)?;
    std::fs::write(output, content)?;
    Ok(())
}

#[derive(Debug, Clone)]
struct TreeNode {
    parsed: bool,
    children: Vec<usize>,
    name: Option<String>,
    has_parent: bool,
    visited: bool,
}

fn visit_tree(nodes: &mut [TreeNode], current: usize, depth: i32) {
    for _ in 0..depth {
        print!("    ")
    }
    print!("- ");
    if let Some(name) = &nodes[current].name {
        println!("{}", name);
    } else {
        println!("{}", current);
    }
    for child in nodes[current].children.clone() {
        visit_tree(nodes, child, depth + 1);
    }
    nodes[current].visited = true;
}

fn scan(pak: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;

    let mut nodes = vec![
        TreeNode {
            parsed: false,
            children: vec![],
            name: None,
            has_parent: false,
            visited: false,
        };
        pak.get_file_count().try_into().unwrap()
    ];

    for index in 0..pak.get_file_count() {
        let content = pak
            .read_file_at(index)
            .context(format!("Failed to open file at {}", index))?;
        if content.len() < 3 {
            continue;
        }

        if &content[0..3] == b"USR" {
            let user = User::new(Cursor::new(&content))
                .context(format!("Failed to open USER at {}", index))?;
            let index: usize = index.try_into()?;
            nodes[index].parsed = true;

            let children = user
                .children
                .into_iter()
                .map(|c| c.name)
                .chain(user.resource_names);

            for child in children {
                let (cindex, _) = if let Ok(found) = pak.find_file(&child) {
                    found
                } else {
                    println!("missing {}", child);
                    continue;
                };
                let cindex: usize = cindex.raw().try_into()?;
                nodes[cindex].name = Some(child);
                nodes[cindex].has_parent = true;
                nodes[index].children.push(cindex);
            }
        } else if &content[0..3] == b"PFB" {
            let pfb = Pfb::new(Cursor::new(&content))
                .context(format!("Failed to open PFB at {}", index))?;
            let index: usize = index.try_into()?;
            nodes[index].parsed = true;

            let children = pfb
                .children
                .into_iter()
                .map(|c| c.name)
                .chain(pfb.resource_names);

            for child in children {
                let (cindex, _) = if let Ok(found) = pak.find_file(&child) {
                    found
                } else {
                    println!("missing {}", child);
                    continue;
                };
                let cindex: usize = cindex.raw().try_into()?;
                nodes[cindex].name = Some(child);
                nodes[cindex].has_parent = true;
                nodes[index].children.push(cindex);
            }
        } else if &content[0..3] == b"SCN" {
            let scn = Scn::new(Cursor::new(&content))
                .context(format!("Failed to open SCN at {}", index))?;
            let index: usize = index.try_into()?;
            nodes[index].parsed = true;

            let children = scn
                .children
                .into_iter()
                .map(|c| c.name)
                .chain(scn.resource_a_names)
                .chain(scn.resource_b_names);

            for child in children {
                let (cindex, _) = if let Ok(found) = pak.find_file(&child) {
                    found
                } else {
                    println!("missing {}", child);
                    continue;
                };
                let cindex: usize = cindex.raw().try_into()?;
                nodes[cindex].name = Some(child);
                nodes[cindex].has_parent = true;
                nodes[index].children.push(cindex);
            }
        }
    }

    for index in 0..nodes.len() {
        if !nodes[index].parsed || nodes[index].has_parent {
            continue;
        }

        visit_tree(&mut nodes, index, 0);
    }

    let named = nodes.iter().filter(|p| p.name.is_some()).count();
    println!("Named file ratio = {}", named as f64 / nodes.len() as f64);

    for user in nodes {
        if user.parsed && !user.visited {
            bail!("Cycle detected")
        }
    }

    println!("Done");
    Ok(())
}

fn gen_json(pak: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;
    let pedia = extract::gen_pedia(&mut pak)?;
    let json = serde_json::to_string_pretty(&pedia)?;
    println!("{}", json);
    Ok(())
}

async fn upload_s3(
    path: PathBuf,
    len: u64,
    mime: &str,
    bucket: String,
    key: String,
    client: &S3Client,
) -> Result<()> {
    use futures::StreamExt;
    use tokio_util::codec;
    let file = tokio::fs::File::open(path).await?;
    let stream =
        codec::FramedRead::new(file, codec::BytesCodec::new()).map(|r| r.map(|r| r.freeze()));
    let request = PutObjectRequest {
        bucket,
        key,
        body: Some(ByteStream::new(stream)),
        content_length: Some(i64::try_from(len)?),
        content_type: Some(mime.to_owned()),
        ..PutObjectRequest::default()
    };
    client.put_object(request).await?;
    Ok(())
}

fn upload_s3_folder(path: &Path, bucket: String, client: &S3Client) -> Result<()> {
    use futures::future::try_join_all;
    use tokio::runtime::Runtime;
    let mut futures = vec![];
    for entry in WalkDir::new(path) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let len = entry.metadata()?.len();
        let mime = match entry
            .path()
            .extension()
            .context("Missing extension")?
            .to_str()
            .context("Extension is not UTF-8")?
        {
            "html" => "text/html",
            "css" => "text/css",
            "js" => "text/javascript",
            "png" => "image/png",
            _ => bail!("Unknown extension"),
        };

        let key = entry
            .path()
            .strip_prefix(path)?
            .to_str()
            .context("Path contain non UTF-8 character")?
            .to_owned();

        futures.push(upload_s3(
            entry.into_path(),
            len,
            mime,
            bucket.clone(),
            key,
            client,
        ));
    }

    Runtime::new()?.block_on(try_join_all(futures))?;

    Ok(())
}

fn gen_website(pak: String, output: String, s3: Option<String>) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;
    let pedia = extract::gen_pedia(&mut pak)?;
    extract::gen_website(pedia, &output)?;
    extract::gen_resources(&mut pak, &Path::new(&output).to_owned().join("resources"))?;
    if let Some(bucket) = s3 {
        println!("Uploading to S3...");
        let s3client = S3Client::new(Region::UsEast1);
        upload_s3_folder(Path::new(&output), bucket, &s3client)?;
    }

    Ok(())
}

fn read_tdb(tdb: String) -> Result<()> {
    let _ = Tdb::new(File::open(tdb)?)?;
    Ok(())
}

fn read_msg(msg: String) -> Result<()> {
    let msg = Msg::new(File::open(msg)?)?;
    println!("{}", serde_json::to_string_pretty(&msg)?);
    Ok(())
}

fn scan_msg(pak: String, output: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;
    let count = pak.get_file_count();
    for i in 0..count {
        let file = pak.read_file_at(i)?;
        if file.len() < 8 || file[4..8] != b"GMSG"[..] {
            continue;
        }
        let msg = Msg::new(Cursor::new(&file)).context(format!("at {}", i))?;
        std::fs::write(
            PathBuf::from(&output).join(format!("{}.txt", i)),
            serde_json::to_string_pretty(&msg)?,
        )?;
    }
    Ok(())
}

fn scan_mesh(pak: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;
    let count = pak.get_file_count();
    for i in 0..count {
        let file = pak.read_file_at(i)?;
        if file.len() < 4 || file[0..4] != b"MESH"[..] {
            continue;
        }
        let _ = Mesh::new(Cursor::new(&file)).context(format!("at {}", i))?;
    }
    Ok(())
}

fn scan_rcol(pak: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;
    let count = pak.get_file_count();

    for i in 0..count {
        let file = pak.read_file_at(i)?;
        if file.len() < 4 || file[0..4] != b"RCOL"[..] {
            continue;
        }
        let _ = Rcol::new(Cursor::new(&file), false).context(format!("at {}", i))?;
    }

    Ok(())
}

fn grep(pak: String, pattern: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;
    println!("Searching for patterns \"{}\"", &pattern);
    let count = pak.get_file_count();
    let re = RegexBuilder::new(&pattern).unicode(false).build()?;
    for i in 0..count {
        let file = pak.read_file_at(i)?;
        if re.is_match(&file) {
            println!("Matched @ {}", i);
        }
    }
    Ok(())
}

fn search_path(pak: String) -> Result<()> {
    let pak = Mutex::new(PakReader::new(File::open(pak)?)?);
    let count = pak.lock().unwrap().get_file_count();
    let counter = std::sync::atomic::AtomicU32::new(0);
    let paths: std::collections::BTreeMap<String, Option<u32>> = (0..count)
        .into_par_iter()
        .map(|index| {
            let file = pak.lock().unwrap().read_file_at(index)?;
            let mut paths = vec![];
            for &suffix in suffix::SUFFIX_MAP.keys() {
                let mut full_suffix = vec![0; (suffix.len() + 2) * 2];
                full_suffix[0] = b'.';
                for (i, &c) in suffix.as_bytes().iter().enumerate() {
                    full_suffix[i * 2 + 2] = c;
                }
                for (suffix_pos, window) in file.windows(full_suffix.len()).enumerate() {
                    if window != full_suffix {
                        continue;
                    }
                    let end = suffix_pos + full_suffix.len() - 2;
                    let mut begin = suffix_pos;
                    loop {
                        if begin < 2 {
                            break;
                        }
                        let earlier = begin - 2;
                        if !file[earlier].is_ascii_graphic() {
                            break;
                        }
                        if file[earlier + 1] != 0 {
                            break;
                        }

                        begin = earlier;
                    }
                    let mut path = String::new();
                    for pos in (begin..end).step_by(2) {
                        path.push(char::from(file[pos]));
                    }
                    let index = pak.lock().unwrap().find_file(&path).ok().map(|x| x.0.raw());
                    paths.push((path, index));
                }
            }

            let counter_prev = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if counter_prev % 100 == 0 {
                eprintln!("{}", counter_prev)
            }

            Ok(paths)
        })
        .flat_map_iter(|paths: Result<_>| paths.unwrap())
        .collect();

    for (path, index) in paths {
        println!("{} $ {:?}", path, index);
    }

    Ok(())
}

fn dump_tree(pak: String, list: String, output: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;
    let mut visited = vec![false; usize::try_from(pak.get_file_count())?];
    let list = File::open(list)?;
    for line in BufReader::new(list).lines() {
        let line = line?;
        let path = line.split(' ').next().context("Empty line")?;
        let index = if let Ok((index, _)) = pak.find_file(path) {
            index
        } else {
            continue;
        };
        let path = PathBuf::from(&output).join(path);
        std::fs::create_dir_all(path.parent().context("no parent")?)?;
        std::fs::write(path, &pak.read_file(index)?)?;
        visited[usize::try_from(index.raw())?] = true;
    }

    for (index, visited) in visited.into_iter().enumerate() {
        if visited {
            continue;
        }
        let path = PathBuf::from(&output)
            .join("_unknown")
            .join(format!("{}", index));
        std::fs::create_dir_all(path.parent().context("no parent")?)?;
        std::fs::write(path, &pak.read_file_at(u32::try_from(index)?)?)?;
    }

    Ok(())
}

fn dump_mesh(mesh: String, output: String) -> Result<()> {
    let mesh = Mesh::new(File::open(mesh)?)?;
    mesh.dump(output)?;
    Ok(())
}

fn dump_rcol(rcol: String) -> Result<()> {
    let rcol = Rcol::new(File::open(rcol)?, true)?;
    rcol.dump()?;
    Ok(())
}

fn dump_meat(mesh: String, rcol: String, output: String) -> Result<()> {
    use std::io::*;
    let mesh = Mesh::new(File::open(mesh)?)?;
    let mut rcol = Rcol::new(File::open(rcol)?, true)?;

    rcol.apply_skeleton(&mesh)?;
    let (vertexs, indexs) = rcol.color_monster_model(&mesh)?;

    let mut output = File::create(output)?;

    writeln!(output, "ply")?;
    writeln!(output, "format ascii 1.0")?;
    writeln!(output, "element vertex {}", vertexs.len())?;
    writeln!(output, "property float x")?;
    writeln!(output, "property float y")?;
    writeln!(output, "property float z")?;
    writeln!(output, "property float red")?;
    writeln!(output, "property float green")?;
    writeln!(output, "property float blue")?;
    writeln!(output, "element face {}", indexs.len() / 3)?;
    writeln!(output, "property list uchar int vertex_index")?;
    writeln!(output, "end_header")?;

    let colors = [
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0],
        [1.0, 1.0, 0.0],
        [1.0, 0.0, 1.0],
        [0.0, 1.0, 1.0],
        [1.0, 0.5, 0.0],
        [0.5, 1.0, 0.0],
        [1.0, 0.0, 0.5],
        [0.5, 0.0, 1.0],
        [0.0, 1.0, 0.5],
        [0.0, 0.5, 1.0],
    ];

    for vertex in vertexs {
        let color = if let Some(meat) = vertex.meat {
            colors[meat]
        } else {
            [0.5, 0.5, 0.5]
        };
        writeln!(
            output,
            "{} {} {} {} {} {}",
            vertex.position.x, -vertex.position.z, vertex.position.y, color[0], color[1], color[2]
        )?;
    }

    for index in indexs.chunks(3) {
        writeln!(output, "3 {} {} {}", index[0], index[1], index[2])?;
    }

    Ok(())
}

fn gen_meat(pak: String, index: u32, output: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;

    let mesh_path = format!("enemy/em{0:03}/00/mod/em{0:03}_00.mesh", index);
    let rcol_path = format!(
        "enemy/em{0:03}/00/collision/em{0:03}_00_colliders.rcol",
        index
    );
    let (mesh, _) = pak.find_file(&mesh_path)?;
    let (rcol, _) = pak.find_file(&rcol_path)?;
    let mesh = Mesh::new(Cursor::new(pak.read_file(mesh)?))?;
    let mut rcol = Rcol::new(Cursor::new(pak.read_file(rcol)?), true)?;
    rcol.apply_skeleton(&mesh)?;
    let (vertexs, indexs) = rcol.color_monster_model(&mesh)?;

    let gpu::HitzoneDiagram { meat, .. } = gpu::gen_hitzone_diagram(vertexs, indexs)?;

    meat.save_png(Path::new(&output))?;

    Ok(())
}

fn gen_resources(pak: String, output: String) -> Result<()> {
    let mut pak = PakReader::new(File::open(pak)?)?;

    extract::gen_resources(&mut pak, Path::new(&output))?;

    Ok(())
}

fn main() -> Result<()> {
    match Mhrice::from_args() {
        Mhrice::Dump { pak, name, output } => dump(pak, name, output),
        Mhrice::DumpIndex { pak, index, output } => dump_index(pak, index, output),
        Mhrice::Scan { pak } => scan(pak),
        Mhrice::GenJson { pak } => gen_json(pak),
        Mhrice::GenWebsite { pak, output, s3 } => gen_website(pak, output, s3),
        Mhrice::ReadTdb { tdb } => read_tdb(tdb),
        Mhrice::ReadMsg { msg } => read_msg(msg),
        Mhrice::ScanMsg { pak, output } => scan_msg(pak, output),
        Mhrice::Grep { pak, pattern } => grep(pak, pattern),
        Mhrice::SearchPath { pak } => search_path(pak),
        Mhrice::DumpTree { pak, list, output } => dump_tree(pak, list, output),
        Mhrice::ScanMesh { pak } => scan_mesh(pak),
        Mhrice::ScanRcol { pak } => scan_rcol(pak),
        Mhrice::DumpMesh { mesh, output } => dump_mesh(mesh, output),
        Mhrice::DumpRcol { rcol } => dump_rcol(rcol),
        Mhrice::DumpMeat { mesh, rcol, output } => dump_meat(mesh, rcol, output),
        Mhrice::GenMeat { pak, index, output } => gen_meat(pak, index, output),
        Mhrice::GenResources { pak, output } => gen_resources(pak, output),
    }
}
