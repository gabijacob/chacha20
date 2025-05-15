pub fn imprime_bloco(label: &str, bloco: &[u32; 16]) {
    println!("{}:", label);
    for i in 0..16 {
        print!("{:08x} ", bloco[i]);
        if (i + 1) % 4 == 0 { print!("\n"); }
    }
    print!("\n");
}