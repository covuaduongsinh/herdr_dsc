use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::c_void,
    mem::{size_of, MaybeUninit},
    path::PathBuf,
    ptr::{copy_nonoverlapping, null_mut},
};

use windows_sys::{
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    Win32::{
        Foundation::{
            CloseHandle, GlobalFree, LocalFree, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
            STATUS_SUCCESS, UNICODE_STRING,
        },
        System::{
            Console::GetConsoleWindow,
            DataExchange::{
                CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable,
                OpenClipboard, SetClipboardData,
            },
            Diagnostics::{
                Debug::ReadProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                    TH32CS_SNAPPROCESS,
                },
            },
            JobObjects::IsProcessInJob,
            Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE},
            Ole::{CF_DIB, CF_DIBV5, CF_UNICODETEXT},
            Threading::{
                GetCurrentProcess, GetExitCodeProcess, OpenProcess, TerminateProcess,
                DETACHED_PROCESS, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_VM_READ,
            },
        },
        UI::Shell::{CommandLineToArgvW, ShellExecuteW},
    },
};

use super::{ClipboardImage, ForegroundJob, Signal};

const STILL_ACTIVE: u32 = 259;

pub(crate) fn should_draw_host_cursor_by_default() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsProcessEntry {
    pid: u32,
    parent_pid: u32,
    name: String,
    argv0: Option<String>,
    argv: Option<Vec<String>>,
    cmdline: Option<String>,
}

pub fn raise_server_nofile_limit() {}

fn raw_command_shell(comspec: Option<std::ffi::OsString>) -> std::ffi::OsString {
    comspec
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into())
}

pub(crate) fn detached_custom_command_process_platform(command: &str) -> std::process::Command {
    detached_custom_command_process_with_comspec(command, std::env::var_os("ComSpec"))
}

fn detached_custom_command_process_with_comspec(
    command: &str,
    comspec: Option<std::ffi::OsString>,
) -> std::process::Command {
    use std::os::windows::process::CommandExt;

    let mut process = std::process::Command::new(raw_command_shell(comspec));
    process.arg("/d").arg("/c").raw_arg(command);
    process
}

pub(crate) fn pane_custom_command_pty_builder_platform(
    command: &str,
) -> portable_pty::CommandBuilder {
    pane_custom_command_pty_builder_with_comspec(command, std::env::var_os("ComSpec"))
}

fn pane_custom_command_pty_builder_with_comspec(
    command: &str,
    comspec: Option<std::ffi::OsString>,
) -> portable_pty::CommandBuilder {
    let mut builder = portable_pty::CommandBuilder::new(raw_command_shell(comspec));
    builder.arg("/d");
    builder.arg("/c");
    builder.raw_arg(command);
    builder
}

pub(crate) fn scrollback_editor_argv(path: &std::path::Path) -> std::io::Result<Vec<String>> {
    let editor = std::env::var("VISUAL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });
    scrollback_editor_argv_with_env(path, editor.as_deref())
}

fn scrollback_editor_argv_with_env(
    path: &std::path::Path,
    editor: Option<&str>,
) -> std::io::Result<Vec<String>> {
    let mut argv = match editor.filter(|value| !value.trim().is_empty()) {
        Some(editor) => command_line_to_argv(editor).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("failed to parse editor command {editor:?}"),
            )
        })?,
        None => vec!["notepad.exe".to_string()],
    };
    if argv.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "editor command must not be empty",
        ));
    }
    argv.push(path.display().to_string());
    Ok(argv)
}

pub fn detach_server_daemon_command(command: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;

    command.creation_flags(DETACHED_PROCESS);
}

pub fn current_process_is_detached_server_daemon() -> bool {
    if !unsafe { GetConsoleWindow() }.is_null() {
        return false;
    }

    let mut in_job = 0;
    unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut in_job) != 0 && in_job == 0 }
}

pub fn foreground_job(child_pid: u32) -> Option<ForegroundJob> {
    let entries = snapshot_processes();
    select_pane_foreground_job(child_pid, &entries)
}

pub fn foreground_group_leader_job(process_group_id: u32) -> Option<ForegroundJob> {
    let entries = snapshot_processes();
    let entry = entries.iter().find(|entry| entry.pid == process_group_id)?;
    Some(ForegroundJob {
        process_group_id,
        processes: vec![foreground_process_from_entry(entry)],
    })
}

pub fn foreground_process_group_id(child_pid: u32) -> Option<u32> {
    foreground_job(child_pid).map(|job| job.process_group_id)
}

pub fn process_cwd(pid: u32) -> Option<PathBuf> {
    let process = ProcessHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)?;
    let process_parameters = read_process_parameters(process.0)?;
    read_unicode_string(process.0, process_parameters.current_directory.dos_path)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

fn select_pane_foreground_job(
    shell_pid: u32,
    entries: &[WindowsProcessEntry],
) -> Option<ForegroundJob> {
    let shell = entries.iter().find(|entry| entry.pid == shell_pid)?;
    let shell_job = || ForegroundJob {
        process_group_id: shell_pid,
        processes: vec![foreground_process_from_entry(shell)],
    };

    let descendants = descendant_entries(shell_pid, entries);
    let mut candidates = Vec::new();
    for entry in &descendants {
        let process = foreground_process_from_entry(entry);
        let job = ForegroundJob {
            process_group_id: entry.pid,
            processes: vec![process],
        };
        if let Some((agent, _)) = crate::detect::identify_agent_in_job(&job) {
            candidates.push((*entry, agent));
        }
    }

    match candidates.len() {
        1 => candidates
            .pop()
            .map(|(entry, _)| foreground_job_from_entry(entry)),
        _ => select_single_agent_chain_candidate(&candidates, entries).map_or_else(
            || Some(shell_job()),
            |entry| Some(foreground_job_from_entry(entry)),
        ),
    }
}

fn foreground_job_from_entry(entry: &WindowsProcessEntry) -> ForegroundJob {
    ForegroundJob {
        process_group_id: entry.pid,
        processes: vec![foreground_process_from_entry(entry)],
    }
}

fn select_single_agent_chain_candidate<'a>(
    candidates: &[(&'a WindowsProcessEntry, crate::detect::Agent)],
    entries: &[WindowsProcessEntry],
) -> Option<&'a WindowsProcessEntry> {
    let (_, first_agent) = candidates.first()?;
    if !candidates.iter().all(|(_, agent)| agent == first_agent) {
        return None;
    }

    let parent_by_pid: HashMap<u32, u32> = entries
        .iter()
        .map(|entry| (entry.pid, entry.parent_pid))
        .collect();

    candidates.iter().map(|(entry, _)| *entry).find(|entry| {
        candidates.iter().all(|(other, _)| {
            entry.pid == other.pid || process_is_ancestor(entry.pid, other.pid, &parent_by_pid)
        })
    })
}

fn process_is_ancestor(
    ancestor_pid: u32,
    descendant_pid: u32,
    parent_by_pid: &HashMap<u32, u32>,
) -> bool {
    let mut current = descendant_pid;
    let mut visited = HashSet::new();
    while visited.insert(current) {
        let Some(parent) = parent_by_pid.get(&current).copied() else {
            return false;
        };
        if parent == ancestor_pid {
            return true;
        }
        if parent == 0 {
            return false;
        }
        current = parent;
    }

    false
}

fn descendant_entries(root_pid: u32, entries: &[WindowsProcessEntry]) -> Vec<&WindowsProcessEntry> {
    let mut children: HashMap<u32, Vec<&WindowsProcessEntry>> = HashMap::new();
    for entry in entries {
        children.entry(entry.parent_pid).or_default().push(entry);
    }

    let mut output = Vec::new();
    let mut queue = VecDeque::new();
    let mut visited = HashSet::new();
    visited.insert(root_pid);
    if let Some(root_children) = children.get(&root_pid) {
        for entry in root_children.iter().copied() {
            if visited.insert(entry.pid) {
                queue.push_back(entry);
            }
        }
    }
    while let Some(entry) = queue.pop_front() {
        output.push(entry);
        if let Some(next) = children.get(&entry.pid) {
            for child in next.iter().copied() {
                if visited.insert(child.pid) {
                    queue.push_back(child);
                }
            }
        }
    }
    output
}

fn foreground_process_from_entry(entry: &WindowsProcessEntry) -> super::ForegroundProcess {
    super::ForegroundProcess {
        pid: entry.pid,
        name: entry.name.clone(),
        argv0: entry.argv0.clone(),
        argv: entry.argv.clone(),
        cmdline: entry.cmdline.clone(),
    }
}

fn snapshot_processes() -> Vec<WindowsProcessEntry> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let _snapshot = ProcessHandle(snapshot);

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut output = Vec::new();
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while ok {
        let pid = entry.th32ProcessID;
        let name = nul_terminated_utf16_to_string(&entry.szExeFile);
        let cmdline = process_command_line(pid);
        let argv = cmdline.as_deref().and_then(command_line_to_argv);
        let argv0 = argv
            .as_ref()
            .and_then(|argv| argv.first().cloned())
            .or_else(|| (!name.is_empty()).then(|| name.clone()));
        output.push(WindowsProcessEntry {
            pid,
            parent_pid: entry.th32ParentProcessID,
            name,
            argv0,
            argv,
            cmdline,
        });
        ok = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    output
}

fn process_command_line(pid: u32) -> Option<String> {
    let process = ProcessHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)?;
    let parameters = read_process_parameters(process.0)?;
    read_unicode_string(process.0, parameters.command_line)
}

fn read_process_parameters(process: HANDLE) -> Option<RtlUserProcessParameters> {
    let mut basic_info = MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            ProcessBasicInformation,
            basic_info.as_mut_ptr().cast::<c_void>(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut(),
        )
    };
    if status != STATUS_SUCCESS as NTSTATUS {
        return None;
    }

    let basic_info = unsafe { basic_info.assume_init() };
    if basic_info.PebBaseAddress.is_null() {
        return None;
    }

    let peb = read_process_value::<Peb>(process, basic_info.PebBaseAddress.cast::<c_void>())?;
    if peb.process_parameters.is_null() {
        return None;
    }

    read_process_value::<RtlUserProcessParameters>(process, peb.process_parameters.cast())
}

fn command_line_to_argv(command_line: &str) -> Option<Vec<String>> {
    let wide: Vec<u16> = command_line
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut argc = 0;
    let argv_ptr = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut argc) };
    if argv_ptr.is_null() || argc <= 0 {
        return None;
    }

    let argv_slice = unsafe { std::slice::from_raw_parts(argv_ptr, argc as usize) };
    let mut argv = Vec::with_capacity(argc as usize);
    for &arg in argv_slice {
        if arg.is_null() {
            continue;
        }
        let mut len = 0;
        unsafe {
            while *arg.add(len) != 0 {
                len += 1;
            }
            argv.push(String::from_utf16_lossy(std::slice::from_raw_parts(
                arg, len,
            )));
        }
    }
    unsafe {
        LocalFree(argv_ptr.cast());
    }
    Some(argv)
}

fn nul_terminated_utf16_to_string(buffer: &[u16]) -> String {
    let len = buffer
        .iter()
        .position(|&value| value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..len])
}

pub fn session_processes(child_pid: u32) -> Vec<u32> {
    if child_pid == 0 {
        return Vec::new();
    }

    let entries = snapshot_processes();
    session_processes_from_entries(child_pid, &entries)
}

fn session_processes_from_entries(child_pid: u32, entries: &[WindowsProcessEntry]) -> Vec<u32> {
    if !entries.iter().any(|entry| entry.pid == child_pid) {
        return Vec::new();
    }

    let mut pids = vec![child_pid];
    pids.extend(
        descendant_entries(child_pid, entries)
            .into_iter()
            .map(|entry| entry.pid),
    );
    pids
}

pub fn signal_processes(pids: &[u32], signal: Signal) {
    if signal == Signal::Hangup {
        return;
    }

    for &pid in pids {
        let Some(process) = ProcessHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
            continue;
        };
        unsafe {
            TerminateProcess(process.0, 1);
        }
    }
}

pub fn process_exists(pid: u32) -> bool {
    let Some(process) = ProcessHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
        return false;
    };

    let mut exit_code = 0;
    let ok = unsafe { GetExitCodeProcess(process.0, &mut exit_code) } != 0;
    ok && exit_code == STILL_ACTIVE
}

pub fn write_clipboard(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    if text.contains('\0') {
        return false;
    }
    let mut utf16: Vec<u16> = text.encode_utf16().collect();
    utf16.push(0);
    let Some(byte_len) = utf16.len().checked_mul(size_of::<u16>()) else {
        return false;
    };

    unsafe {
        let owner = GetConsoleWindow();
        if owner.is_null() || OpenClipboard(owner) == 0 {
            return false;
        }
        let _clipboard = ClipboardGuard;

        if EmptyClipboard() == 0 {
            return false;
        }

        let memory = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if memory.is_null() {
            return false;
        }

        let locked = GlobalLock(memory);
        if locked.is_null() {
            GlobalFree(memory);
            return false;
        }
        copy_nonoverlapping(utf16.as_ptr(), locked.cast::<u16>(), utf16.len());
        GlobalUnlock(memory);

        if SetClipboardData(CF_UNICODETEXT as u32, memory).is_null() {
            GlobalFree(memory);
            return false;
        }

        true
    }
}

pub fn read_clipboard_text() -> Option<String> {
    None
}

pub fn open_url(url: &str) -> std::io::Result<()> {
    let operation = wide_null("open");
    let url = wide_null(url);
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            url.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        )
    };
    if result as isize > 32 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "failed to open URL with ShellExecuteW: code {}",
            result as isize
        )))
    }
}

#[cfg_attr(windows, allow(dead_code))]
pub fn read_clipboard_image() -> Option<ClipboardImage> {
    unsafe {
        if OpenClipboard(null_mut()) == 0 {
            return None;
        }
        let _clipboard = ClipboardGuard;

        let format = if IsClipboardFormatAvailable(CF_DIBV5 as u32) != 0 {
            CF_DIBV5
        } else if IsClipboardFormatAvailable(CF_DIB as u32) != 0 {
            CF_DIB
        } else {
            return None;
        };

        let handle = GetClipboardData(format as u32);
        if handle.is_null() {
            return None;
        }

        let size = GlobalSize(handle);
        if size == 0 {
            return None;
        }

        let ptr = GlobalLock(handle);
        if ptr.is_null() {
            return None;
        }
        let dib = std::slice::from_raw_parts(ptr.cast::<u8>(), size).to_vec();
        GlobalUnlock(handle);

        let png = dib_to_png(&dib)?;
        if png.len() > crate::protocol::MAX_CLIPBOARD_IMAGE_PAYLOAD {
            return None;
        }
        Some(ClipboardImage {
            bytes: png,
            extension: "png",
        })
    }
}

const BI_RGB: u32 = 0;
const BI_BITFIELDS: u32 = 3;
const MAX_DIB_DIMENSION: usize = 30_000;
const MAX_DIB_PIXELS_BYTES: u64 = 256 * 1024 * 1024;

fn dib_to_png(dib: &[u8]) -> Option<Vec<u8>> {
    if dib.len() < 40 {
        return None;
    }

    let bi_size = u32::from_le_bytes(dib[0..4].try_into().ok()?);
    if bi_size < 40 {
        return None;
    }
    let width_raw = i32::from_le_bytes(dib[4..8].try_into().ok()?);
    let height_raw = i32::from_le_bytes(dib[8..12].try_into().ok()?);
    let bit_count = u16::from_le_bytes(dib[14..16].try_into().ok()?);
    let compression = u32::from_le_bytes(dib[16..20].try_into().ok()?);
    let clr_used = u32::from_le_bytes(dib[32..36].try_into().ok()?);

    if width_raw <= 0 {
        return None;
    }
    let width = width_raw as usize;
    let bottom_up = height_raw > 0;
    let height = if height_raw == i32::MIN {
        return None;
    } else {
        height_raw.checked_abs()? as usize
    };
    if width == 0 || height == 0 {
        return None;
    }
    if width > MAX_DIB_DIMENSION || height > MAX_DIB_DIMENSION {
        return None;
    }
    let pixel_area = (width as u64).checked_mul(height as u64)?;
    if pixel_area.checked_mul(4)? > MAX_DIB_PIXELS_BYTES {
        return None;
    }

    let (bytes_per_pixel, standard_bitfields) = match (bit_count, compression) {
        (24, BI_RGB) => (3usize, false),
        (32, BI_RGB) => (4usize, false),
        (32, BI_BITFIELDS) => (4usize, true),
        _ => return None,
    };

    let palette_bytes: usize = if bit_count <= 8 {
        let entries = if clr_used != 0 {
            clr_used as usize
        } else {
            1usize << bit_count
        };
        entries.checked_mul(4)?
    } else {
        0
    };

    let bi_size = bi_size as usize;
    let row_bits = (bit_count as usize).checked_mul(width)?;
    let stride = (row_bits.checked_add(31)? / 32).checked_mul(4)?;
    let expected_pixel_bytes = stride.checked_mul(height)?;

    let mask_bytes: usize = if standard_bitfields {
        // The standard BGRA mask triple is always readable at a fixed
        // offset of 40 bytes from the header start: the legacy 40-byte
        // BITMAPINFOHEADER has an external RGBQUAD triple starting there,
        // and BITMAPV4HEADER/V5HEADER (biSize 108/124) embed the same
        // three masks as struct fields at that same offset.
        let masks_start = 40usize;
        if dib.len() < masks_start + 12 {
            return None;
        }
        let r_mask = u32::from_le_bytes(dib[masks_start..masks_start + 4].try_into().ok()?);
        let g_mask = u32::from_le_bytes(dib[masks_start + 4..masks_start + 8].try_into().ok()?);
        let b_mask = u32::from_le_bytes(dib[masks_start + 8..masks_start + 12].try_into().ok()?);
        if r_mask != 0x00FF_0000 || g_mask != 0x0000_FF00 || b_mask != 0x0000_00FF {
            return None;
        }

        if bi_size == 40 {
            // A 40-byte header never embeds masks itself; the external
            // RGBQUAD triple is mandatory here.
            12
        } else {
            // BITMAPV4HEADER/V5HEADER already embed the masks, so no extra
            // bytes are needed in principle -- but real-world producers
            // (observed: .NET's `Clipboard.SetImage`) sometimes still emit
            // a redundant legacy-style 12-byte mask triple between the
            // full header and the pixel array anyway. Detect which layout
            // this buffer actually uses by checking which offset makes the
            // remaining bytes match the expected pixel array size exactly,
            // rather than assuming one or the other from header size alone.
            let base = bi_size.checked_add(palette_bytes)?;
            let without_extra = base.checked_add(expected_pixel_bytes)?;
            let with_extra = base.checked_add(12)?.checked_add(expected_pixel_bytes)?;
            if with_extra == dib.len() {
                12
            } else if without_extra == dib.len() {
                0
            } else if dib.len() >= with_extra {
                // Neither fits exactly (there may be trailing profile data
                // etc.) -- prefer the layout observed in practice.
                12
            } else {
                0
            }
        }
    } else {
        0
    };

    let pixel_start = bi_size
        .checked_add(mask_bytes)?
        .checked_add(palette_bytes)?;
    let needed = pixel_start.checked_add(expected_pixel_bytes)?;
    if dib.len() < needed {
        return None;
    }

    let mut rgba = vec![0u8; width.checked_mul(height)?.checked_mul(4)?];
    let mut alpha_accum: u8 = 0;

    for out_y in 0..height {
        let src_y = if bottom_up { height - 1 - out_y } else { out_y };
        let row_start = pixel_start + src_y * stride;
        let row = &dib[row_start..row_start + width * bytes_per_pixel];
        let out_row_start = out_y * width * 4;

        for x in 0..width {
            let src = &row[x * bytes_per_pixel..x * bytes_per_pixel + bytes_per_pixel];
            let (b, g, r) = (src[0], src[1], src[2]);
            let a = if bytes_per_pixel == 4 { src[3] } else { 255 };
            alpha_accum |= a;

            let out_idx = out_row_start + x * 4;
            rgba[out_idx] = r;
            rgba[out_idx + 1] = g;
            rgba[out_idx + 2] = b;
            rgba[out_idx + 3] = a;
        }
    }

    // Many 32bpp DIBs from screenshots leave alpha as zero/garbage; treat an
    // all-zero accumulated alpha (or BI_RGB, which has no defined alpha
    // channel) as "opaque" rather than fully transparent.
    if bytes_per_pixel == 4 && (compression == BI_RGB || alpha_accum == 0) {
        for pixel in rgba.chunks_exact_mut(4) {
            pixel[3] = 255;
        }
    }

    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width as u32, height as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().ok()?;
        writer.write_image_data(&rgba).ok()?;
    }
    Some(out)
}

pub fn show_desktop_notification(_title: &str, _body: Option<&str>) -> std::io::Result<bool> {
    Ok(false)
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct ProcessHandle(HANDLE);

struct ClipboardGuard;

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        unsafe {
            CloseClipboard();
        }
    }
}

impl ProcessHandle {
    fn open(pid: u32, access: u32) -> Option<Self> {
        if pid == 0 {
            return None;
        }
        let handle = unsafe { OpenProcess(access, 0, pid) };
        (!handle.is_null()).then_some(Self(handle))
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Peb {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: [u8; 1],
    reserved3: [*mut c_void; 2],
    ldr: *mut c_void,
    process_parameters: *mut RtlUserProcessParameters,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CurDir {
    dos_path: UNICODE_STRING,
    handle: HANDLE,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtlUserProcessParameters {
    maximum_length: u32,
    length: u32,
    flags: u32,
    debug_flags: u32,
    console_handle: HANDLE,
    console_flags: u32,
    standard_input: HANDLE,
    standard_output: HANDLE,
    standard_error: HANDLE,
    current_directory: CurDir,
    dll_path: UNICODE_STRING,
    image_path_name: UNICODE_STRING,
    command_line: UNICODE_STRING,
}

fn read_process_value<T: Copy>(process: HANDLE, address: *const c_void) -> Option<T> {
    if address.is_null() {
        return None;
    }

    let mut value = MaybeUninit::<T>::uninit();
    let mut bytes_read = 0;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            address,
            value.as_mut_ptr().cast::<c_void>(),
            size_of::<T>(),
            &mut bytes_read,
        )
    } != 0;

    (ok && bytes_read == size_of::<T>()).then(|| unsafe { value.assume_init() })
}

fn read_unicode_string(process: HANDLE, unicode: UNICODE_STRING) -> Option<String> {
    if unicode.Buffer.is_null() || unicode.Length == 0 || !unicode.Length.is_multiple_of(2) {
        return None;
    }

    let char_len = usize::from(unicode.Length / 2);
    let mut buffer = vec![0_u16; char_len];
    let mut bytes_read = 0;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            unicode.Buffer.cast::<c_void>(),
            buffer.as_mut_ptr().cast::<c_void>(),
            usize::from(unicode.Length),
            &mut bytes_read,
        )
    } != 0;

    if !ok || bytes_read != usize::from(unicode.Length) {
        return None;
    }

    String::from_utf16(&buffer).ok()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use windows_sys::Win32::System::Console::{AllocConsole, FreeConsole, GetConsoleWindow};

    const DETACHED_CONSOLE_TEST_CHILD_ENV: &str = "HERDR_TEST_DETACHED_CONSOLE_CHILD";

    #[test]
    fn server_daemon_command_does_not_inherit_console() {
        if std::env::var_os(DETACHED_CONSOLE_TEST_CHILD_ENV).is_some() {
            assert!(unsafe { GetConsoleWindow() }.is_null());
            return;
        }

        let allocated_console = if unsafe { GetConsoleWindow() }.is_null() {
            assert_ne!(unsafe { AllocConsole() }, 0, "allocate test console");
            true
        } else {
            false
        };

        let test_exe = std::env::current_exe().expect("resolve test executable");
        let mut child = Command::new(test_exe);
        child
            .arg("server_daemon_command_does_not_inherit_console")
            .env(DETACHED_CONSOLE_TEST_CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        super::detach_server_daemon_command(&mut child);

        let status = child.status().expect("spawn detached test child");
        if allocated_console {
            unsafe {
                FreeConsole();
            }
        }

        assert!(
            status.success(),
            "detached child inherited the test console"
        );
    }

    fn argv_strings(argv: &[std::ffi::OsString]) -> Vec<String> {
        argv.into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn pane_custom_command_uses_cmd() {
        let builder = super::pane_custom_command_pty_builder_with_comspec(
            "echo hello",
            Some(r"C:\Windows\System32\cmd.exe".into()),
        );

        assert_eq!(
            argv_strings(builder.get_argv()),
            [r"C:\Windows\System32\cmd.exe", "/d", "/c"]
        );
    }

    #[test]
    fn detached_custom_command_uses_cmd() {
        let expected_shell = std::env::var_os("ComSpec")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into())
            .to_string_lossy()
            .into_owned();

        let process = super::detached_custom_command_process_platform("echo hello");

        assert_eq!(process.get_program().to_string_lossy(), expected_shell);
        assert_eq!(
            process
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["/d", "/c", "echo hello"]
        );
    }

    #[test]
    fn custom_command_falls_back_when_comspec_is_empty() {
        let builder =
            super::pane_custom_command_pty_builder_with_comspec("echo hello", Some("".into()));

        assert_eq!(
            argv_strings(builder.get_argv()),
            [r"C:\Windows\System32\cmd.exe", "/d", "/c"]
        );
    }

    #[test]
    fn detached_custom_command_preserves_quoted_command_tail() {
        let path = std::env::temp_dir().join(format!(
            "herdr-raw-command-quotes-{}.txt",
            std::process::id()
        ));
        let command = format!(r#"echo "hi" > "{}""#, path.display());

        let status = super::detached_custom_command_process_platform(&command)
            .status()
            .expect("spawn raw command");

        assert!(status.success(), "{status:?}");
        let content = std::fs::read_to_string(&path).expect("read command output");
        let _ = std::fs::remove_file(&path);
        assert!(content.contains(r#""hi""#), "{content:?}");
        assert!(!content.contains(r#"\"hi\""#), "{content:?}");
    }

    #[test]
    fn windows_process_cwd_reads_child_launch_directory() {
        let cwd = std::env::temp_dir().join(format!("herdr-cwd-test-{}", std::process::id()));
        fs::create_dir_all(&cwd).expect("create cwd fixture");

        let shell =
            std::env::var_os("ComSpec").unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into());
        let mut child = Command::new(shell)
            .args(["/D", "/Q", "/C", "ping -n 11 127.0.0.1 > NUL"])
            .current_dir(&cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cmd");

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut observed = None;
        while Instant::now() < deadline {
            observed = super::process_cwd(child.id());
            if observed.as_deref() == Some(cwd.as_path()) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&cwd);

        assert_eq!(observed.as_deref(), Some(cwd.as_path()));
    }

    #[test]
    fn windows_process_tree_selects_direct_agent_descendant() {
        let entries = vec![
            test_entry(10, 1, "powershell.exe", &["powershell.exe"]),
            test_entry(20, 10, "codex.exe", &["codex.exe"]),
        ];

        let job = super::select_pane_foreground_job(10, &entries).unwrap();

        assert_eq!(job.process_group_id, 20);
        assert_eq!(job.processes.len(), 1);
        assert_eq!(job.processes[0].name, "codex.exe");
    }

    #[test]
    fn windows_process_tree_selects_wrapped_agent_descendant() {
        let entries = vec![
            test_entry(10, 1, "cmd.exe", &["cmd.exe"]),
            test_entry(
                20,
                10,
                "node.exe",
                &[
                    "node.exe",
                    "C:\\Users\\herdr\\AppData\\Roaming\\npm\\node_modules\\codex\\bin\\codex.js",
                ],
            ),
        ];

        let job = super::select_pane_foreground_job(10, &entries).unwrap();

        assert_eq!(job.process_group_id, 20);
        assert_eq!(job.processes[0].name, "node.exe");
    }

    #[test]
    fn windows_process_tree_selects_cmd_wrapped_agent_descendant() {
        let entries = vec![
            test_entry(10, 1, "powershell.exe", &["powershell.exe"]),
            test_entry(
                20,
                10,
                "cmd.exe",
                &[
                    "cmd.exe",
                    "/D",
                    "/S",
                    "/C",
                    "C:\\Users\\herdr\\AppData\\Roaming\\npm\\codex.cmd --model gpt-5",
                ],
            ),
        ];

        let job = super::select_pane_foreground_job(10, &entries).unwrap();

        assert_eq!(job.process_group_id, 20);
        assert_eq!(job.processes[0].name, "cmd.exe");
    }

    #[test]
    fn windows_process_tree_selects_topmost_codex_process_in_single_agent_chain() {
        let entries = vec![
            test_entry(10, 1, "powershell.exe", &["powershell.exe"]),
            test_entry(
                20,
                10,
                "node.exe",
                &[
                    "node.exe",
                    "C:\\Users\\herdr\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\bin\\codex.js",
                ],
            ),
            test_entry(
                30,
                20,
                "codex.exe",
                &["C:\\Users\\herdr\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\node_modules\\@openai\\codex-win32-x64\\vendor\\x86_64-pc-windows-msvc\\bin\\codex.exe"],
            ),
            test_entry(40, 30, "node_repl.exe", &["node_repl.exe"]),
            test_entry(
                50,
                40,
                "codex.exe",
                &["codex.exe", "app-server", "--listen", "stdio://"],
            ),
        ];

        let job = super::select_pane_foreground_job(10, &entries).unwrap();

        assert_eq!(job.process_group_id, 20);
        assert_eq!(job.processes[0].name, "node.exe");
    }

    #[test]
    fn windows_process_tree_selects_topmost_claude_process_in_single_agent_chain() {
        let entries = vec![
            test_entry(10, 1, "powershell.exe", &["powershell.exe"]),
            test_entry(20, 10, "claude.exe", &["claude.exe"]),
            test_entry(30, 20, "claude.exe", &["claude.exe", "mcp-server"]),
        ];

        let job = super::select_pane_foreground_job(10, &entries).unwrap();

        assert_eq!(job.process_group_id, 20);
        assert_eq!(job.processes[0].name, "claude.exe");
    }

    #[test]
    fn windows_process_tree_returns_shell_for_same_agent_siblings() {
        let entries = vec![
            test_entry(10, 1, "powershell.exe", &["powershell.exe"]),
            test_entry(20, 10, "codex.exe", &["codex.exe"]),
            test_entry(30, 10, "codex.exe", &["codex.exe"]),
        ];

        let job = super::select_pane_foreground_job(10, &entries).unwrap();

        assert_eq!(job.process_group_id, 10);
        assert_eq!(job.processes[0].name, "powershell.exe");
    }

    #[test]
    fn windows_process_tree_returns_shell_for_plain_descendant() {
        let entries = vec![
            test_entry(10, 1, "powershell.exe", &["powershell.exe"]),
            test_entry(20, 10, "git.exe", &["git.exe", "status"]),
        ];

        let job = super::select_pane_foreground_job(10, &entries).unwrap();

        assert_eq!(job.process_group_id, 10);
        assert_eq!(job.processes[0].name, "powershell.exe");
    }

    #[test]
    fn windows_process_tree_returns_shell_for_multiple_agent_descendants() {
        let entries = vec![
            test_entry(10, 1, "powershell.exe", &["powershell.exe"]),
            test_entry(20, 10, "codex.exe", &["codex.exe"]),
            test_entry(30, 10, "claude.exe", &["claude.exe"]),
        ];

        let job = super::select_pane_foreground_job(10, &entries).unwrap();

        assert_eq!(job.process_group_id, 10);
        assert_eq!(job.processes[0].name, "powershell.exe");
    }

    #[test]
    fn windows_session_processes_collects_shell_and_descendants() {
        let entries = vec![
            test_entry(10, 1, "powershell.exe", &["powershell.exe"]),
            test_entry(20, 10, "cmd.exe", &["cmd.exe"]),
            test_entry(30, 20, "node.exe", &["node.exe"]),
            test_entry(40, 1, "unrelated.exe", &["unrelated.exe"]),
        ];

        let mut pids = super::session_processes_from_entries(10, &entries);
        pids.sort_unstable();

        assert_eq!(pids, vec![10, 20, 30]);
    }

    #[test]
    fn windows_process_tree_ignores_pid_reuse_cycles() {
        let entries = vec![
            test_entry(10, 30, "powershell.exe", &["powershell.exe"]),
            test_entry(20, 10, "codex.exe", &["codex.exe"]),
            test_entry(30, 20, "node.exe", &["node.exe"]),
        ];

        let descendants = super::descendant_entries(10, &entries);

        assert_eq!(
            descendants
                .iter()
                .map(|entry| entry.pid)
                .collect::<Vec<_>>(),
            vec![20, 30]
        );
    }

    #[test]
    fn windows_process_tree_returns_shell_when_candidate_parent_chain_cycles() {
        let entries = vec![
            test_entry(10, 40, "powershell.exe", &["powershell.exe"]),
            test_entry(20, 10, "codex.exe", &["codex.exe"]),
            test_entry(30, 10, "codex.exe", &["codex.exe"]),
            test_entry(40, 10, "node.exe", &["node.exe"]),
        ];

        let job = super::select_pane_foreground_job(10, &entries).unwrap();

        assert_eq!(job.process_group_id, 10);
        assert_eq!(job.processes[0].name, "powershell.exe");
    }

    #[test]
    fn scrollback_editor_argv_uses_editor_env_and_appends_path() {
        let path = std::path::Path::new(r"C:\Users\User\AppData\Local\Temp\herdr scrollback.txt");
        let argv = super::scrollback_editor_argv_with_env(
            path,
            Some(r#""C:\Program Files\Microsoft VS Code\Code.exe" --wait"#),
        )
        .unwrap();

        assert_eq!(argv[0], r"C:\Program Files\Microsoft VS Code\Code.exe");
        assert_eq!(argv[1], "--wait");
        assert_eq!(argv[2], path.display().to_string());
    }

    #[test]
    fn scrollback_editor_argv_falls_back_to_notepad() {
        let path = std::path::Path::new(r"C:\Temp\herdr-scrollback.txt");
        let argv = super::scrollback_editor_argv_with_env(path, None).unwrap();

        assert_eq!(
            argv,
            vec!["notepad.exe".to_string(), path.display().to_string()]
        );
    }

    fn dib_header(width: i32, height: i32, bit_count: u16, compression: u32) -> [u8; 40] {
        let mut header = [0u8; 40];
        header[0..4].copy_from_slice(&40u32.to_le_bytes());
        header[4..8].copy_from_slice(&width.to_le_bytes());
        header[8..12].copy_from_slice(&height.to_le_bytes());
        header[12..14].copy_from_slice(&1u16.to_le_bytes()); // biPlanes
        header[14..16].copy_from_slice(&bit_count.to_le_bytes());
        header[16..20].copy_from_slice(&compression.to_le_bytes());
        header
    }

    fn decode_png(bytes: &[u8]) -> (u32, u32, Vec<u8>) {
        let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
        let mut reader = decoder.read_info().expect("decode png header");
        let mut buf = vec![0u8; reader.output_buffer_size()];
        let info = reader.next_frame(&mut buf).expect("decode png frame");
        buf.truncate(info.buffer_size());
        (info.width, info.height, buf)
    }

    #[test]
    fn dib_to_png_bottom_up_32bpp_zero_alpha_forces_opaque() {
        let mut dib = dib_header(2, 2, 32, super::BI_RGB).to_vec();
        // Bottom-up: first row in memory is the bottom (visual) row.
        // Bottom row (memory row 0): red, green
        dib.extend_from_slice(&[0, 0, 255, 0]); // B,G,R,A = red, alpha 0
        dib.extend_from_slice(&[0, 255, 0, 0]); // green, alpha 0
                                                // Top row (memory row 1): blue, white
        dib.extend_from_slice(&[255, 0, 0, 0]); // blue, alpha 0
        dib.extend_from_slice(&[255, 255, 255, 0]); // white, alpha 0

        let png_bytes = super::dib_to_png(&dib).expect("valid 32bpp dib");
        let (width, height, pixels) = decode_png(&png_bytes);
        assert_eq!((width, height), (2, 2));

        // Visual row 0 (top of image) must be the top memory row: blue, white.
        assert_eq!(&pixels[0..4], &[0, 0, 255, 255]);
        assert_eq!(&pixels[4..8], &[255, 255, 255, 255]);
        // Visual row 1 (bottom of image): red, green.
        assert_eq!(&pixels[8..12], &[255, 0, 0, 255]);
        assert_eq!(&pixels[12..16], &[0, 255, 0, 255]);
    }

    #[test]
    fn dib_to_png_24bpp_with_row_padding() {
        let mut dib = dib_header(2, 2, 24, super::BI_RGB).to_vec();
        // stride = ((24*2+31)/32)*4 = 8, so each 6-byte row has 2 padding bytes.
        // Bottom-up, memory row 0 = bottom visual row.
        dib.extend_from_slice(&[0, 0, 255, 0, 255, 0, 0xAA, 0xBB]); // red, green + padding
        dib.extend_from_slice(&[255, 0, 0, 255, 255, 255, 0xCC, 0xDD]); // blue, white + padding

        let png_bytes = super::dib_to_png(&dib).expect("valid 24bpp dib");
        let (width, height, pixels) = decode_png(&png_bytes);
        assert_eq!((width, height), (2, 2));

        assert_eq!(&pixels[0..4], &[0, 0, 255, 255]);
        assert_eq!(&pixels[4..8], &[255, 255, 255, 255]);
        assert_eq!(&pixels[8..12], &[255, 0, 0, 255]);
        assert_eq!(&pixels[12..16], &[0, 255, 0, 255]);
    }

    #[test]
    fn dib_to_png_top_down_negative_height_no_flip() {
        let mut dib = dib_header(2, -2, 32, super::BI_RGB).to_vec();
        // Top-down: memory row 0 is the visual top row.
        dib.extend_from_slice(&[0, 0, 255, 0]); // red
        dib.extend_from_slice(&[0, 255, 0, 0]); // green
        dib.extend_from_slice(&[255, 0, 0, 0]); // blue
        dib.extend_from_slice(&[255, 255, 255, 0]); // white

        let png_bytes = super::dib_to_png(&dib).expect("valid top-down dib");
        let (_, _, pixels) = decode_png(&png_bytes);

        assert_eq!(&pixels[0..4], &[255, 0, 0, 255]); // red
        assert_eq!(&pixels[4..8], &[0, 255, 0, 255]); // green
        assert_eq!(&pixels[8..12], &[0, 0, 255, 255]); // blue
        assert_eq!(&pixels[12..16], &[255, 255, 255, 255]); // white
    }

    #[test]
    fn dib_to_png_preserves_genuine_alpha() {
        // BI_RGB has no defined alpha channel, so genuine (non-zero) alpha is
        // only meaningful with BI_BITFIELDS and standard BGRA masks.
        let mut dib = dib_header(1, 1, 32, super::BI_BITFIELDS).to_vec();
        dib.extend_from_slice(&0x00FF_0000u32.to_le_bytes()); // R mask
        dib.extend_from_slice(&0x0000_FF00u32.to_le_bytes()); // G mask
        dib.extend_from_slice(&0x0000_00FFu32.to_le_bytes()); // B mask
        dib.extend_from_slice(&[0, 0, 255, 128]); // red, alpha 128

        let png_bytes = super::dib_to_png(&dib).expect("valid dib with alpha");
        let (_, _, pixels) = decode_png(&png_bytes);
        assert_eq!(&pixels[0..4], &[255, 0, 0, 128]);
    }

    /// Builds a BITMAPV5HEADER-sized (124-byte) header with the standard
    /// BGRA masks embedded at their struct offset (40), as V4/V5 headers do.
    fn v5_header(width: i32, height: i32, bit_count: u16, compression: u32) -> Vec<u8> {
        let mut header = vec![0u8; 124];
        header[0..4].copy_from_slice(&124u32.to_le_bytes());
        header[4..8].copy_from_slice(&width.to_le_bytes());
        header[8..12].copy_from_slice(&height.to_le_bytes());
        header[12..14].copy_from_slice(&1u16.to_le_bytes());
        header[14..16].copy_from_slice(&bit_count.to_le_bytes());
        header[16..20].copy_from_slice(&compression.to_le_bytes());
        header[40..44].copy_from_slice(&0x00FF_0000u32.to_le_bytes());
        header[44..48].copy_from_slice(&0x0000_FF00u32.to_le_bytes());
        header[48..52].copy_from_slice(&0x0000_00FFu32.to_le_bytes());
        header
    }

    #[test]
    fn dib_to_png_v5_header_with_redundant_external_mask_table() {
        // Real-world quirk (observed from .NET's `Clipboard.SetImage`): some
        // producers emit a BITMAPV5HEADER (which already embeds the color
        // masks as struct fields) but *also* append a redundant legacy-style
        // 12-byte RGBQUAD mask triple before the pixel array, exactly like a
        // 40-byte BITMAPINFOHEADER would require. Confirms the buffer-size
        // based detection in `dib_to_png` picks the right pixel offset.
        let mut dib = v5_header(1, 1, 32, super::BI_BITFIELDS);
        dib.extend_from_slice(&0x00FF_0000u32.to_le_bytes()); // redundant R mask
        dib.extend_from_slice(&0x0000_FF00u32.to_le_bytes()); // redundant G mask
        dib.extend_from_slice(&0x0000_00FFu32.to_le_bytes()); // redundant B mask
        dib.extend_from_slice(&[0, 0, 255, 128]); // red, alpha 128

        let png_bytes = super::dib_to_png(&dib).expect("valid v5 dib with redundant mask table");
        let (_, _, pixels) = decode_png(&png_bytes);
        assert_eq!(&pixels[0..4], &[255, 0, 0, 128]);
    }

    #[test]
    fn dib_to_png_v5_header_without_redundant_mask_table() {
        // The spec-compliant layout: BITMAPV5HEADER's embedded masks are
        // used and the pixel array follows the header immediately.
        let mut dib = v5_header(1, 1, 32, super::BI_BITFIELDS);
        dib.extend_from_slice(&[0, 0, 255, 128]); // red, alpha 128

        let png_bytes = super::dib_to_png(&dib).expect("valid v5 dib without redundant mask table");
        let (_, _, pixels) = decode_png(&png_bytes);
        assert_eq!(&pixels[0..4], &[255, 0, 0, 128]);
    }

    #[test]
    fn dib_to_png_rejects_indexed_color() {
        let dib = dib_header(2, 2, 8, super::BI_RGB).to_vec();
        assert!(super::dib_to_png(&dib).is_none());
    }

    #[test]
    fn dib_to_png_rejects_truncated_buffer() {
        let mut dib = dib_header(4, 4, 32, super::BI_RGB).to_vec();
        dib.extend_from_slice(&[0u8; 8]); // way short of the 4*4*4 = 64 bytes needed
        assert!(super::dib_to_png(&dib).is_none());
    }

    #[test]
    fn dib_to_png_rejects_unsupported_bit_depth() {
        let dib = dib_header(2, 2, 16, super::BI_RGB).to_vec();
        assert!(super::dib_to_png(&dib).is_none());
    }

    /// Exercises the REAL Win32 clipboard path end-to-end (OpenClipboard,
    /// IsClipboardFormatAvailable, GetClipboardData, GlobalLock/GlobalSize),
    /// not synthetic DIB bytes. Requires a real image to already be on the
    /// Windows clipboard (e.g. via `[System.Windows.Forms.Clipboard]::SetImage`
    /// in PowerShell before running). Ignored by default since it depends on
    /// external clipboard state and is not headless-CI-safe.
    #[test]
    #[ignore]
    fn read_clipboard_image_reads_real_clipboard_4x3_test_bitmap() {
        let image = super::read_clipboard_image().expect(
            "expected an image on the clipboard -- set one first, e.g. via \
             PowerShell [System.Windows.Forms.Clipboard]::SetImage(...)",
        );
        assert_eq!(image.extension, "png");

        let decoder = png::Decoder::new(std::io::Cursor::new(&image.bytes));
        let mut reader = decoder
            .read_info()
            .expect("decode real clipboard png header");
        assert_eq!(reader.info().width, 4);
        assert_eq!(reader.info().height, 3);
        let mut buf = vec![0u8; reader.output_buffer_size()];
        let info = reader
            .next_frame(&mut buf)
            .expect("decode real clipboard png frame");
        buf.truncate(info.buffer_size());

        let pixel = |x: usize, y: usize| -> [u8; 4] {
            let idx = (y * 4 + x) * 4;
            [buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]]
        };
        assert_eq!(pixel(0, 0), [255, 0, 0, 255], "top-left should be red");
        assert_eq!(pixel(1, 0), [0, 255, 0, 255], "should be green");
        assert_eq!(pixel(2, 0), [0, 0, 255, 255], "should be blue");
        assert_eq!(pixel(3, 0), [255, 255, 0, 255], "should be yellow");
        assert_eq!(pixel(0, 1), [255, 0, 255, 255], "should be magenta");
        assert_eq!(pixel(1, 1), [0, 255, 255, 255], "should be cyan");
        assert_eq!(pixel(2, 1), [255, 255, 255, 255], "should be white");
        assert_eq!(pixel(3, 1), [0, 0, 0, 255], "should be black");
        assert_eq!(pixel(0, 2), [128, 128, 128, 255], "should be gray");
        assert_eq!(pixel(1, 2), [64, 32, 16, 255]);
        assert_eq!(pixel(2, 2), [10, 20, 30, 255]);
        assert_eq!(pixel(3, 2), [200, 150, 100, 255]);

        let out_path = std::env::temp_dir().join("herdr-clipboard-test-output.png");
        std::fs::write(&out_path, &image.bytes).expect("write decoded clipboard png to disk");
        eprintln!("wrote real clipboard capture to {}", out_path.display());
    }

    fn test_entry(
        pid: u32,
        parent_pid: u32,
        name: &str,
        argv: &[&str],
    ) -> super::WindowsProcessEntry {
        super::WindowsProcessEntry {
            pid,
            parent_pid,
            name: name.to_string(),
            argv0: argv.first().map(|value| (*value).to_string()),
            argv: Some(argv.iter().map(|value| (*value).to_string()).collect()),
            cmdline: Some(argv.join(" ")),
        }
    }
}
