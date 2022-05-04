use std::{os::raw, path::Path, ffi::CString};
use thiserror::Error;
use std::ptr;

#[derive(Error, Debug)]
pub enum ZipError {
    #[error("StreamError")]
    StreamError,
    #[error("DataError")]
    DataError,
    #[error("MemError")]
    MemError,
    #[error("BufError")]
    BufError,
    #[error("VersionError")]
    VersionError,
    #[error("EndOfList")]
    EndOfList,
    #[error("EndOfStream")]
    EndOfStream,
    #[error("ParamError")]
    ParamError,
    #[error("FormatError")]
    FormatError,
    #[error("InternalError")]
    InternalError,
    #[error("CrcError")]
    CrcError,
    #[error("CryptError")]
    CryptError,
    #[error("ExistError")]
    ExistError,
    #[error("PasswordError")]
    PasswordError,
    #[error("SupportError")]
    SupportError,
    #[error("HashError")]
    HashError,
    #[error("OpenError")]
    OpenError,
    #[error("CloseError")]
    CloseError,
    #[error("SeekError")]
    SeekError,
    #[error("TellError")]
    TellError,
    #[error("ReadError")]
    ReadError,
    #[error("WriteError")]
    WriteError,
    #[error("SignError")]
    SignError,
    #[error("SymlinkError")]
    SymlinkError,
    #[error("UnknwonError")]
    UnknownError,
}

impl From<i32> for ZipError {
    fn from(num: i32) -> ZipError {
        match num {
            jotaro_sys::MZ_STREAM_ERROR =>   Self::StreamError,
            jotaro_sys::MZ_DATA_ERROR =>     Self::DataError,
            jotaro_sys::MZ_MEM_ERROR =>      Self::MemError,
            jotaro_sys::MZ_BUF_ERROR =>      Self::BufError,
            jotaro_sys::MZ_VERSION_ERROR =>  Self::VersionError,
            jotaro_sys::MZ_END_OF_LIST =>    Self::EndOfList,
            jotaro_sys::MZ_END_OF_STREAM =>  Self::EndOfStream,
            jotaro_sys::MZ_PARAM_ERROR =>    Self::ParamError,
            jotaro_sys::MZ_FORMAT_ERROR =>   Self::FormatError,
            jotaro_sys::MZ_INTERNAL_ERROR => Self::InternalError,
            jotaro_sys::MZ_CRC_ERROR =>      Self::CrcError,
            jotaro_sys::MZ_CRYPT_ERROR =>    Self::CryptError,
            jotaro_sys::MZ_EXIST_ERROR =>    Self::ExistError,
            jotaro_sys::MZ_PASSWORD_ERROR => Self::PasswordError,
            jotaro_sys::MZ_SUPPORT_ERROR =>  Self::SupportError,
            jotaro_sys::MZ_HASH_ERROR =>     Self::HashError,
            jotaro_sys::MZ_OPEN_ERROR =>     Self::OpenError,
            jotaro_sys::MZ_CLOSE_ERROR =>    Self::CloseError,
            jotaro_sys::MZ_SEEK_ERROR =>     Self::SeekError,
            jotaro_sys::MZ_TELL_ERROR =>     Self::TellError,
            jotaro_sys::MZ_READ_ERROR =>     Self::ReadError,
            jotaro_sys::MZ_WRITE_ERROR =>    Self::WriteError,
            jotaro_sys::MZ_SIGN_ERROR =>     Self::SignError,
            jotaro_sys::MZ_SYMLINK_ERROR =>  Self::SymlinkError,
            _ =>                             Self::UnknownError,
        }
    }
}

pub enum CompressMethod {
    Store,
    Deflate,
    Bzip2,
    Lzma,
    Zstd,
    Xz,
    Aes,
}

pub struct ZipWriter {
    handle: *mut raw::c_void,
    password: Option<CString>,
}

impl ZipWriter {
    pub fn new() -> Self {
        let mut handle: *mut raw::c_void = ptr::null_mut();
        unsafe {
            let ret = jotaro_sys::mz_zip_writer_create(&mut handle);
            if ret == ptr::null_mut() {     /* This should be rare enough to warrant a panic */
                panic!("Failed to create ZipWriter");
            }
        }

        Self {
            handle,
            password: None,
        }
    }

    pub fn is_open(&mut self) -> bool {
        unsafe {
            let ret = jotaro_sys::mz_zip_writer_is_open(self.handle);
            ret == jotaro_sys::MZ_OK
        }
    }

    fn path_to_cstring<P: AsRef<Path>>(path: P) -> Result<CString, ZipError> {
        let s = path
            .as_ref()
            .to_str()
            .ok_or(ZipError::InternalError)?;
        let cs = CString::new(s)
            .map_err(|_| { ZipError::InternalError })?;
        Ok(cs)
    }

    fn str_to_cstring(s: &str) -> Result<CString, ZipError> {
        CString::new(s)
            .map_err(|_| { ZipError::InternalError })
    }

    pub fn open_file<P: AsRef<Path>>(&mut self, path: P, disk_size: i64, append: bool) -> Result<(), ZipError> {
        unsafe {
            let ret = jotaro_sys::mz_zip_writer_open_file(
                self.handle,
                Self::path_to_cstring(path)?.as_ptr(),
                disk_size,
                if append { 1 } else { 0 });
            if ret == jotaro_sys::MZ_OK {
                Ok(())
            } else {
                Err(ZipError::from(ret))
            }
        }
    }

    pub fn close(&mut self) -> Result<(), ZipError> {
        if self.is_open() {
            unsafe {
                let ret = jotaro_sys::mz_zip_writer_close(self.handle);
                if ret != jotaro_sys::MZ_OK {
                    Err(ZipError::from(ret))
                } else {
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn set_password(&mut self, password: &str) -> Result<(), ZipError> {
        self.password = Some(CString::new(password).map_err(|_| { ZipError::ParamError })?);
        unsafe {
            /* Password buffer must be alive for the duration of the writer */
            jotaro_sys::mz_zip_writer_set_password(self.handle, self.password.as_ref().unwrap().as_ptr());
        }
        Ok(())
    }

    pub fn set_aes(&mut self, aes: bool) {
        unsafe {
            jotaro_sys::mz_zip_writer_set_aes(self.handle, if aes { 1 } else { 0 })
        }
    }

    pub fn set_compress_method(&mut self, method: CompressMethod) {
        let method_int = match method {
            CompressMethod::Store => jotaro_sys::MZ_COMPRESS_METHOD_STORE,
            CompressMethod::Deflate => jotaro_sys::MZ_COMPRESS_METHOD_DEFLATE,
            CompressMethod::Bzip2 => jotaro_sys::MZ_COMPRESS_METHOD_BZIP2,
            CompressMethod::Lzma => jotaro_sys::MZ_COMPRESS_METHOD_LZMA,
            CompressMethod::Zstd => jotaro_sys::MZ_COMPRESS_METHOD_ZSTD,
            CompressMethod::Xz => jotaro_sys::MZ_COMPRESS_METHOD_XZ,
            CompressMethod::Aes => jotaro_sys::MZ_COMPRESS_METHOD_AES,
        };

        unsafe {
            jotaro_sys::mz_zip_writer_set_compress_method(self.handle, method_int as u16);
        }
    }

    pub fn set_compress_level(&mut self, level: i32) -> Result<(), ZipError> {
        if level < -1 || level > 9 {
            return Err(ZipError::ParamError);
        }
        
        unsafe {
            jotaro_sys::mz_zip_writer_set_compress_level(self.handle, level as i16);
        }
        Ok(())
    }

    pub fn add_file<P: AsRef<Path>>(&mut self, path: P, name: &str) -> Result<(), ZipError> {
        unsafe {
            let ret = jotaro_sys::mz_zip_writer_add_file(
                self.handle,
                Self::path_to_cstring(path)?.as_ptr(),
                Self::str_to_cstring(name)?.as_ptr());
            if ret != jotaro_sys::MZ_OK {
                return Err(ZipError::from(ret));
            }
        }
        Ok(())
    }
}

impl Drop for ZipWriter {
    fn drop(&mut self) {
        let _ = self.close();
        unsafe {
            jotaro_sys::mz_zip_writer_delete(&mut self.handle);
        }
    }
}



#[cfg(test)]
mod tests {
    use crate::{ZipWriter, CompressMethod};

    #[test]
    fn it_works() {
        let mut zw = ZipWriter::new();
        zw.open_file("/tmp/test.zip", 0, false)
            .expect("open_file() failed");
        let _ = zw.set_password("oraora");
        zw.set_aes(true);
        zw.set_compress_method(CompressMethod::Store);
        zw.add_file("/etc/profile", "profile")
            .expect("add_file() failed");
    }
}
