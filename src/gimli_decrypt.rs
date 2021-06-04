use crate::gimli_common::gimli;
use std::io;

pub struct GimliAeadDecryptIter {
  state: [u32; 12],
  cipher_message_len: usize,
  cipher_message: Box<dyn Iterator<Item = Result<u8, io::Error>>>,
  output_buffer: Vec<u8>,
}

impl GimliAeadDecryptIter {
  pub fn new(
    key: [u8; 32],
    nonce: [u8; 16],
    cipher_text_len: usize,
    cipher_text: Box<dyn Iterator<Item = Result<u8, io::Error>>>,
    mut associated_data: &[u8],
  ) -> Self {
    let message_len = cipher_text_len - 16;
    let mut state: [u32; 12] = [0; 12];
    let state_8 = unsafe { std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48) };

    // Init state with key and nonce plus first permute
    state_8[..16].clone_from_slice(&nonce);
    state_8[16..48].clone_from_slice(&key);
    gimli(&mut state);

    // Handle associated data
    while associated_data.len() >= 16 {
      let state_8 = unsafe { std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48) };
      for i in 0..16 {
        state_8[i] ^= associated_data[i]
      }
      gimli(&mut state);
      associated_data = &associated_data[16 as usize..];
    }
    let state_8 = unsafe { std::slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 48) };
    for i in 0..associated_data.len() {
      state_8[i] ^= associated_data[i]
    }
    state_8[associated_data.len() as usize] ^= 1;
    state_8[47] ^= 1;
    gimli(&mut state);

    GimliAeadDecryptIter {
      state: state,
      cipher_message_len: message_len,
      cipher_message: cipher_text,
      output_buffer: Vec::new(),
    }
  }
}

impl Iterator for GimliAeadDecryptIter {
  type Item = u8;
  fn next(&mut self) -> Option<Self::Item> {
    if self.output_buffer.len() > 0 {
      return Some(self.output_buffer.remove(0));
    }
    let state_8 = unsafe { std::slice::from_raw_parts_mut(self.state.as_mut_ptr() as *mut u8, 48) };

    if self.cipher_message_len >= 16 {
      for i in 0..16 {
        let current_byte = self
          .cipher_message
          .next()
          .unwrap()
          .expect("Read error on input");
        self.output_buffer.push(state_8[i] ^ current_byte);
        state_8[i] = current_byte;
        self.cipher_message_len -= 1;
      }
      gimli(&mut self.state);
      return Some(self.output_buffer.remove(0));
    }

    if self.cipher_message_len <= 15 && self.cipher_message_len > 0 {
      for i in 0..self.cipher_message_len {
        let current_byte = self
          .cipher_message
          .next()
          .unwrap()
          .expect("Read error on input");
        self.output_buffer.push(state_8[i] ^ current_byte);
        state_8[i] = current_byte;
      }
      state_8[self.cipher_message_len as usize] ^= 1;
      state_8[47] ^= 1;
      gimli(&mut self.state);
      let state_8 =
        unsafe { std::slice::from_raw_parts_mut(self.state.as_mut_ptr() as *mut u8, 48) };
      self.cipher_message_len = 0;
      // Handle tag
      let mut result: u32 = 0;
      for i in 0..16 {
        let current_byte = self
          .cipher_message
          .next()
          .unwrap()
          .expect("Read error on input");
        result |= (current_byte ^ state_8[i]) as u32;
      }
      result = result.overflowing_sub(1).0;
      result = result >> 16;
      assert_ne!(result, 0); // Need a better way to express an error than panic
      match self.output_buffer.len() {
        0 => return None,
        _ => return Some(self.output_buffer.remove(0)),
      }
    }
    None
  }
}
