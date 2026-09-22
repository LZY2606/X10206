mod common;
use common::Harness;
#[test]
fn dbg_mixing() {
    let mut h = Harness::new(3, 2, 6, 2);
    let g0 = h.make_complete_source_with_gaps(0, |s, i| !(s == 0 && (i == 2 || i == 4)));
    h.import(&g0);
    let shards1 = h.all_shards(1);
    let files = vec![(1usize, 0usize, shards1[0].clone(), Some("g1".to_string()))];
    let g1 = h.make_source(1, &files, |_, _| true);
    h.import(&g1);
    h.run(false);
    let conn = h.db.conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT stripe_index,generation,rank,feasible,substr(stripe_digest,1,12) FROM outcomes ORDER BY stripe_index,id").unwrap();
    for r in stmt.query_map([], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,String>(4)?))).unwrap() { println!("{:?}", r.unwrap()); }
}
