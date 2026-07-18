use crate::crypto::U8_32;
use crate::random::fill_random_bytes;

#[repr(C)]
pub struct PayloadInfo {
    pub iat_rva: u32,
    pub iat_size: u32,
    pub base_key: U8_32,
    _pad: [u8; PayloadInfo::PADDING_SIZE],
}

impl PayloadInfo {
    const TOTAL_SIZE: usize = 128;
    const PADDING_SIZE: usize = Self::TOTAL_SIZE - size_of::<U8_32>() - (size_of::<u32>() * 2);

    pub fn new(base_key: U8_32, iat_rva: u32, iat_size: u32) -> Self {
        let mut rand_pad = [0u8; Self::PADDING_SIZE];
        fill_random_bytes(&mut rand_pad);

        Self {
            iat_rva,
            iat_size,
            base_key,
            _pad: rand_pad,
        }
    }
}

const _: () = assert!(size_of::<PayloadInfo>() == PayloadInfo::TOTAL_SIZE);
