use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Instant;

/// 字节限流器核心结构体，使用令牌桶算法，单位字节。
#[derive(Debug)]
pub struct ByteRateLimiter {
    capacity: u64,
    tokens: u64,
    refill_rate: f64, // 每秒补充字节数
    last_refill: Instant,
}

impl ByteRateLimiter {
    /// 初始化字节限流器。
    /// # 参数
    /// - capacity: 令牌桶最大容量（字节，支持突发）
    /// - refill_rate: 每秒补充字节数（>0）
    /// # Panics
    /// 如果 capacity == 0 或 refill_rate <= 0，则 panic。
    pub fn new(capacity: u64, refill_rate: f64) -> Self {
        if capacity == 0 || refill_rate <= 0.0 {
            panic!("Invalid parameters: capacity must be >0, refill_rate >0");
        }
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// 尝试获取指定字节数的令牌（非阻塞）。
    /// 先补充令牌，然后如果 tokens >= size，消耗 size 并返回 true；否则 false。
    pub fn try_acquire_bytes(&mut self, size: u64) -> bool {
        self.refill();
        if size <= self.tokens {
            self.tokens -= size;
            true
        } else {
            false
        }
    }

    /// 获取当前可用令牌数（字节，只读）。
    pub fn tokens(&self) -> u64 {
        self.tokens
    }

    /// 动态设置补充速率（字节/秒）。
    pub fn set_rate(&mut self, rate: f64) {
        if rate > 0.0 {
            self.refill_rate = rate;
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = (elapsed * self.refill_rate).floor() as u64;
        if new_tokens > 0 {
            self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }
}

/// 并发安全的字节限流器包装器。
#[derive(Clone)]
pub struct ConcurrentByteRateLimiter {
    inner: Arc<Mutex<ByteRateLimiter>>,
}

impl ConcurrentByteRateLimiter {
    pub fn new(capacity: u64, refill_rate: f64) -> Self {
        let inner = ByteRateLimiter::new(capacity, refill_rate);
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub fn try_acquire_bytes(&self, size: u64) -> bool {
        let mut guard = self.inner.lock();
        guard.try_acquire_bytes(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_acquire() {
        let mut limiter = ByteRateLimiter::new(1000, 1000.0);
        assert!(limiter.try_acquire_bytes(500));
        assert!(!limiter.try_acquire_bytes(600)); // 拒绝
    }
}
