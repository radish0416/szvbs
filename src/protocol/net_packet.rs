impl<B: AsRef<[u8]>> NetPacket<B> {
    pub fn protocol(&self) -> Protocol {
        // 假设协议类型在 buffer[0]
        if let Some(byte) = self.buffer().as_ref().get(0) {
            Protocol::from(*byte)
        } else {
            Protocol::Unknown(0)
        }
    }
}
