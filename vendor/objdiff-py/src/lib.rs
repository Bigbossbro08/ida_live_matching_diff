use pyo3::prelude::*;

#[pyclass(module = "objdiff_py", unsendable)]
pub struct ObjectBuilder {
    obj: object::write::Object<'static>,
    sections: Vec<object::write::SectionId>,
    symbols: Vec<object::write::SymbolId>,
}

#[pymethods]
impl ObjectBuilder {
    #[new]
    pub fn new(arch: &str) -> PyResult<Self> {
        let (format, architecture, endianness) = match arch.to_lowercase().as_str() {
            "x86" | "i386" => (
                object::BinaryFormat::Coff,
                object::Architecture::I386,
                object::Endianness::Little,
            ),
            "x86_64" | "x64" | "amd64" => (
                object::BinaryFormat::Coff,
                object::Architecture::X86_64,
                object::Endianness::Little,
            ),
            "arm" => (
                object::BinaryFormat::Coff,
                object::Architecture::Arm,
                object::Endianness::Little,
            ),
            "arm64" | "aarch64" => (
                object::BinaryFormat::Coff,
                object::Architecture::Aarch64,
                object::Endianness::Little,
            ),
            "ppc" | "powerpc" => (
                object::BinaryFormat::Elf,
                object::Architecture::PowerPc,
                object::Endianness::Big,
            ),
            "mips" => (
                object::BinaryFormat::Elf,
                object::Architecture::Mips,
                object::Endianness::Big,
            ),
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Unsupported arch: {}",
                    arch
                )));
            }
        };
        let mut obj = object::write::Object::new(format, architecture, endianness);
        if format == object::BinaryFormat::Coff {
            obj.flags = object::FileFlags::Coff {
                characteristics: object::pe::IMAGE_FILE_LINE_NUMS_STRIPPED,
            };
            // MSVC stores '?'-mangled and already-underscored names verbatim. The
            // default CoffI386 mangling prepends '_' to every Text/Data symbol, which
            // corrupts them (OBJDIFF_SYNTH_FIDELITY_PLAN.md §2).
            obj.set_mangling(object::write::Mangling::Coff);
        }
        Ok(Self {
            obj,
            sections: Vec::new(),
            symbols: Vec::new(),
        })
    }

    pub fn add_section(&mut self, name: &str, segment: &str, kind: u8) -> PyResult<u64> {
        let section_kind = match kind {
            0 => object::SectionKind::Text,
            1 => object::SectionKind::Data,
            2 => object::SectionKind::ReadOnlyData,
            3 => object::SectionKind::UninitializedData,
            4 => object::SectionKind::ReadOnlyString,
            5 => object::SectionKind::OtherString,
            _ => object::SectionKind::Other,
        };
        let sec_id = self.obj.add_section(
            segment.as_bytes().to_vec(),
            name.as_bytes().to_vec(),
            section_kind,
        );
        let idx = self.sections.len() as u64;
        self.sections.push(sec_id);
        Ok(idx)
    }

    pub fn write_bytes(&mut self, section_id: u64, offset: u64, data: &[u8]) -> PyResult<()> {
        let sec_id = self
            .sections
            .get(section_id as usize)
            .ok_or_else(|| pyo3::exceptions::PyIndexError::new_err("Invalid section_id"))?;
        let section = self.obj.section_mut(*sec_id);

        if section.is_bss() {
            let target_end = offset + data.len() as u64;
            if target_end > section.data().len() as u64 {
                section.append_bss(target_end - section.data().len() as u64, 4);
            }
            return Ok(());
        }

        let current_len = section.data().len();
        let target_end = offset as usize + data.len();
        if current_len < target_end {
            if offset as usize > current_len {
                let gap = vec![0u8; offset as usize - current_len];
                section.append_data(&gap, 1);
                section.append_data(data, 1);
            } else {
                let (in_place, extra) = data.split_at(current_len - offset as usize);
                section.data_mut()[offset as usize..current_len].copy_from_slice(in_place);
                section.append_data(extra, 1);
            }
        } else {
            section.data_mut()[offset as usize..target_end].copy_from_slice(data);
        }
        Ok(())
    }

    pub fn add_symbol(
        &mut self,
        section_id: u64,
        name: &str,
        value: u64,
        size: u64,
        kind: u8,
        flags: u8,
    ) -> PyResult<u64> {
        let sym_kind = match kind {
            0 => object::SymbolKind::Unknown,
            2 => object::SymbolKind::Text,
            3 => object::SymbolKind::Data,
            4 => object::SymbolKind::Section,
            5 => object::SymbolKind::File,
            6 => object::SymbolKind::Label,
            _ => object::SymbolKind::Unknown,
        };
        let scope = if (flags & 1) != 0 {
            object::SymbolScope::Compilation
        } else {
            object::SymbolScope::Linkage
        };
        let weak = (flags & 2) != 0;
        let section = if section_id == u64::MAX || section_id == 0xFFFF_FFFF || (flags & 4) != 0 {
            object::write::SymbolSection::Undefined
        } else if (flags & 8) != 0 {
            object::write::SymbolSection::Common
        } else if (flags & 16) != 0 {
            object::write::SymbolSection::Absolute
        } else {
            let sec_id = self
                .sections
                .get(section_id as usize)
                .ok_or_else(|| pyo3::exceptions::PyIndexError::new_err("Invalid section_id"))?;
            object::write::SymbolSection::Section(*sec_id)
        };
        let sym_id = self.obj.add_symbol(object::write::Symbol {
            name: name.as_bytes().to_vec(),
            value,
            size,
            kind: sym_kind,
            scope,
            weak,
            section,
            flags: object::SymbolFlags::None,
        });
        let idx = self.symbols.len() as u64;
        self.symbols.push(sym_id);
        Ok(idx)
    }

    pub fn add_relocation(
        &mut self,
        section_id: u64,
        offset: u64,
        symbol_id: u64,
        kind: u8,
        size: u8,
        addend: i64,
    ) -> PyResult<()> {
        let sec_id = self
            .sections
            .get(section_id as usize)
            .ok_or_else(|| pyo3::exceptions::PyIndexError::new_err("Invalid section_id"))?;
        let sym_id = self
            .symbols
            .get(symbol_id as usize)
            .ok_or_else(|| pyo3::exceptions::PyIndexError::new_err("Invalid symbol_id"))?;

        let reloc_size = match size {
            1 => 8,
            2 | 16 => 16,
            4 | 32 => 32,
            8 | 64 => 64,
            _ => 32,
        };
        let reloc_kind = match kind {
            0 | 6 => object::RelocationKind::Absolute,
            1 if reloc_size == 16 => object::RelocationKind::Absolute,
            1 | 20 => object::RelocationKind::Relative,
            2 | 7 => object::RelocationKind::Absolute,
            11 => object::RelocationKind::SectionOffset,
            _ => object::RelocationKind::Absolute,
        };
        self.obj
            .add_relocation(
                *sec_id,
                object::write::Relocation {
                    offset,
                    symbol: *sym_id,
                    addend,
                    flags: object::RelocationFlags::Generic {
                        kind: reloc_kind,
                        encoding: object::RelocationEncoding::Generic,
                        size: reloc_size,
                    },
                },
            )
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Failed to add relocation: {:?}",
                    e
                ))
            })?;
        Ok(())
    }

    pub fn finish(&mut self, py: Python) -> PyResult<PyObject> {
        let bytes = self.obj.write().map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to write object: {:?}", e))
        })?;
        Ok(pyo3::types::PyBytes::new(py, &bytes).into())
    }
}

fn object_diff_to_py(py: Python, obj_diff: &objdiff_core::diff::ObjectDiff) -> PyResult<PyObject> {
    let dict = pyo3::types::PyDict::new(py);
    let symbols = pyo3::types::PyList::empty(py);
    for sym in &obj_diff.symbols {
        let sym_dict = pyo3::types::PyDict::new(py);
        sym_dict.set_item("target_symbol", sym.target_symbol)?;
        sym_dict.set_item("match_percent", sym.match_percent)?;
        if let Some((score, max_score)) = sym.diff_score {
            let score_list = pyo3::types::PyList::new(py, &[score, max_score])?;
            sym_dict.set_item("diff_score", score_list)?;
        } else {
            sym_dict.set_item("diff_score", py.None())?;
        }
        symbols.append(sym_dict)?;
    }
    dict.set_item("symbols", symbols)?;
    let sections = pyo3::types::PyList::empty(py);
    for sec in &obj_diff.sections {
        let sec_dict = pyo3::types::PyDict::new(py);
        sec_dict.set_item("match_percent", sec.match_percent)?;
        sections.append(sec_dict)?;
    }
    dict.set_item("sections", sections)?;
    Ok(dict.into())
}

#[pyfunction]
pub fn diff_objects(py: Python, left_obj: &[u8], right_obj: &[u8]) -> PyResult<PyObject> {
    let diff_config = objdiff_core::diff::DiffObjConfig::default();
    let left_parsed = objdiff_core::obj::read::parse(
        left_obj,
        &diff_config,
        objdiff_core::diff::DiffSide::Target,
    )
    .map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Failed to parse left object: {:?}", e))
    })?;
    let right_parsed = objdiff_core::obj::read::parse(
        right_obj,
        &diff_config,
        objdiff_core::diff::DiffSide::Base,
    )
    .map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Failed to parse right object: {:?}", e))
    })?;

    let mapping_config = objdiff_core::diff::MappingConfig::default();
    let diff_result = objdiff_core::diff::diff_objs(
        Some(&left_parsed),
        Some(&right_parsed),
        None,
        &diff_config,
        &mapping_config,
    )
    .map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Failed to diff objects: {:?}", e))
    })?;

    let out_dict = pyo3::types::PyDict::new(py);
    if let Some(left) = diff_result.left {
        out_dict.set_item("left", object_diff_to_py(py, &left)?)?;
    } else {
        out_dict.set_item("left", py.None())?;
    }
    if let Some(right) = diff_result.right {
        out_dict.set_item("right", object_diff_to_py(py, &right)?)?;
    } else {
        out_dict.set_item("right", py.None())?;
    }
    Ok(out_dict.into())
}

#[pymodule]
fn objdiff_py(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ObjectBuilder>()?;
    m.add_function(wrap_pyfunction!(diff_objects, m)?)?;
    Ok(())
}
