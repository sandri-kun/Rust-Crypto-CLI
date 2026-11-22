pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
// A named file adds a u16 length and up to 240 UTF-8 filename bytes, plus a 20-byte batch binding.
pub const MAX_CONTENT_BYTES: usize = MAX_INPUT_BYTES + 262;
pub const MAX_BASE64_BYTES: usize = (MAX_CONTENT_BYTES + 55).div_ceil(3) * 4;
pub const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PASSWORD_BYTES: usize = 1024;
