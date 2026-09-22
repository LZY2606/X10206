use chamber::gf::GfField;
fn main(){
    let f=GfField::new(4).unwrap();
    let old=vec![vec![1,1,1,1],vec![2,2,2,2]];
    let old_all=f.encode(2,2,&old).unwrap();
    eprintln!("old parity2={:?} parity3={:?}",old_all[2],old_all[3]);
    let known=vec![(0usize,old_all[0].clone()),(1usize,old_all[1].clone())];
    match f.reconstruct(2,2,&known){Ok(v)=>eprintln!("gen1 reconstruct OK {:?}",v),Err(e)=>eprintln!("gen1 ERR {e}")}
    let new=vec![vec![3,3,3,3],vec![4,4,4,4]];
    let new_all=f.encode(2,2,&new).unwrap();
    let known=vec![(0usize,new_all[0].clone()),(1usize,new_all[1].clone())];
    match f.reconstruct(2,2,&known){Ok(v)=>eprintln!("gen2 reconstruct OK {:?}",v),Err(e)=>eprintln!("gen2 ERR {e}")}
}
