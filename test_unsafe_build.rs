// Test build.rs with unsafe blocks and raw pointer manipulation
fn main() {
    // Large unsafe block with allocations
    unsafe {
        let layout = std::alloc::Layout::from_size_align(1024, 8).unwrap();
        let ptr: *mut u8 = std::alloc::alloc(layout);
        *ptr = 42;
        std::ptr::write(ptr.add(1), 43);
        std::ptr::write_volatile(ptr.add(2), 44);
        let _value = std::ptr::read(ptr);
        std::alloc::dealloc(ptr, layout);
    }

    // Raw pointer operations
    let x = 42;
    let raw_ptr = &x as *const i32;
    unsafe {
        println!("Value: {}", *raw_ptr);
    }

    // Transmute (dangerous)
    let bytes: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
    let _num: u32 = unsafe { std::mem::transmute(bytes) };

    // More raw pointer manipulation
    unsafe {
        let mut data = vec![1, 2, 3, 4, 5];
        let ptr = data.as_mut_ptr();
        *ptr.offset(0) = 10;
        *ptr.offset(1) = 20;
        std::ptr::swap(ptr, ptr.offset(1));
    }
}
