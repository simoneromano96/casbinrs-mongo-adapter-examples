use casbin::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let mut e = Enforcer::new(
        "examples/rbac_with_domains_model.conf",
        "examples/rbac_with_domains_policy.csv",
    )
    .await
    .unwrap();

    let mut adapter = MongoAdapter::new("mongodb://casbin_rs:casbin_rs@127.0.0.1/")
        .await
        .unwrap();

    assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());
    e.set_adapter(adapter).await.unwrap();

    let filter = Filter {
        p: vec!["", "domain1"],
        g: vec!["", "", "domain1"],
    };

    e.load_filtered_policy(filter).await.unwrap();
    assert!(e.enforce(("alice", "domain1", "data1", "read")).unwrap());
    assert!(e.enforce(("alice", "domain1", "data1", "write")).unwrap());
    assert!(!e.enforce(("alice", "domain1", "data2", "read")).unwrap());
    assert!(!e.enforce(("alice", "domain1", "data2", "write")).unwrap());
    assert!(!e.enforce(("bob", "domain2", "data2", "read")).unwrap());
    assert!(!e.enforce(("bob", "domain2", "data2", "write")).unwrap());

    Ok(())
}
