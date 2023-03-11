
fn main() {
    let x = vec![1, 2, 3];

    let mut y = x.as_slice().into_iter().cycle();
    println!("{:?}", y.next());
    println!("{:?}", y.next());
    println!("{:?}", y.next());
    println!("{:?}", y.next());
    println!("{:?}", y.next());
    println!("{:?}", y.next());
    println!("{:?}", y.next());
    println!("{:?}", y.next());
}
