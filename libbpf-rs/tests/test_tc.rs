use serial_test::serial;

mod test;
use test::{bump_rlimit_mlock, get_test_object};

use libbpf_rs::{
    Object, TcHook, TcHookBuilder, CUSTOM, EGRESS, INGRESS, TC_H_CLSACT, TC_H_MIN_EGRESS,
    TC_H_MIN_INGRESS,
};
// do all TC tests on the lo network interface
const LO_IFINDEX: i32 = 1;

fn test_helper_get_tc_builder(handle_str: &str) -> (Object, TcHookBuilder, TcHook) {
    let obj = get_test_object("tc-unit.bpf.o");
    let fd = obj.prog(handle_str).unwrap().fd();

    let mut tc_builder = TcHookBuilder::new();
    tc_builder
        .fd(fd)
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);

    // Ensure clean clsact tc qdisc
    let mut destroyer = TcHook::new(fd);
    destroyer.ifindex(LO_IFINDEX).attach_point(EGRESS | INGRESS);

    (obj, tc_builder, destroyer)
}

#[test]
#[serial]
fn test_tc_basic_cycle() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, mut destroyer) = test_helper_get_tc_builder("handle_tc");
    assert!(!destroyer.destroy().is_err());

    let mut egress = tc_builder.hook(EGRESS);
    assert!(!egress.create().is_err());
    assert!(!egress.attach().is_err());
    assert!(!egress.query().is_err());
    assert!(!egress.detach().is_err());
    assert!(!egress.destroy().is_err());
    assert!(!destroyer.destroy().is_err());

    let mut ingress = tc_builder.hook(EGRESS);
    assert!(!ingress.create().is_err());
    assert!(!ingress.attach().is_err());
    assert!(!ingress.query().is_err());
    assert!(!ingress.detach().is_err());
    assert!(!ingress.destroy().is_err());
    assert!(!destroyer.destroy().is_err());

    let mut custom = tc_builder.hook(CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    assert!(!ingress.create().is_err());
    assert!(!custom.attach().is_err());
    assert!(!custom.query().is_err());
    assert!(!custom.detach().is_err());
    assert!(!destroyer.destroy().is_err());
}

#[test]
#[serial]
fn test_tc_attach_no_qdisc() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, mut destroyer) = test_helper_get_tc_builder("handle_tc");
    assert!(!destroyer.destroy().is_err());

    let mut egress = tc_builder.hook(EGRESS);
    let mut ingress = tc_builder.hook(INGRESS);
    let mut custom = tc_builder.hook(CUSTOM);

    assert!(egress.attach().is_err());
    assert!(ingress.attach().is_err());
    assert!(custom.attach().is_err());
}

#[test]
#[serial]
fn test_tc_attach_basic() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, mut destroyer) = test_helper_get_tc_builder("handle_tc");
    assert!(!destroyer.destroy().is_err());

    let mut egress = tc_builder.hook(EGRESS);
    assert!(egress.attach().is_err());
    assert!(!egress.create().is_err());
    assert!(!egress.attach().is_err());
    assert!(!destroyer.destroy().is_err());

    let mut ingress = tc_builder.hook(INGRESS);
    assert!(ingress.attach().is_err());
    assert!(!ingress.create().is_err());
    assert!(!ingress.attach().is_err());
    assert!(!destroyer.destroy().is_err());
}

#[test]
#[serial]
fn test_tc_attach_repeat() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, mut destroyer) = test_helper_get_tc_builder("handle_tc");
    assert!(!destroyer.destroy().is_err());

    let mut egress = tc_builder.hook(EGRESS);
    assert!(!egress.create().is_err());
    for _ in 0..10 {
        assert!(!egress.attach().is_err());
    }

    let mut ingress = tc_builder.hook(INGRESS);
    for _ in 0..10 {
        assert!(!ingress.attach().is_err());
    }

    let mut custom = tc_builder.hook(CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_EGRESS);
    for _ in 0..10 {
        assert!(!custom.attach().is_err());
    }
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    for _ in 0..10 {
        assert!(!custom.attach().is_err());
    }
}

#[test]
#[serial]
fn test_tc_attach_custom() {
    bump_rlimit_mlock();
    let (_obj, tc_builder, mut destroyer) = test_helper_get_tc_builder("handle_tc");
    assert!(!destroyer.destroy().is_err());

    // destroy() ensures that clsact tc qdisc does not exist
    // but BPF hooks need this qdisc in order to attach
    // for ingress and egress hooks, the create() method will
    // ensure that clsact tc qdisc is available, but custom hooks
    // cannot call create(), thus we need to utilize an ingress, egress, or
    // egress|ingress hook to create() and ensure
    // the clsact tc qdisc is available

    let mut custom = tc_builder.hook(CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    assert!(custom.attach().is_err());
    assert!(custom.create().is_err());

    let mut ingress_for_parent = tc_builder.hook(INGRESS);
    assert!(!ingress_for_parent.create().is_err());
    assert!(!custom.attach().is_err());
    assert!(!destroyer.destroy().is_err());
    assert!(custom.attach().is_err());

    custom.parent(TC_H_CLSACT, TC_H_MIN_EGRESS);
    assert!(!ingress_for_parent.create().is_err());
    assert!(!custom.attach().is_err());
    assert!(!destroyer.destroy().is_err());
    assert!(custom.attach().is_err());

    let mut egress_for_parent = tc_builder.hook(EGRESS);
    assert!(!egress_for_parent.create().is_err());
    assert!(!custom.attach().is_err());
    assert!(!destroyer.destroy().is_err());
    assert!(custom.attach().is_err());

    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    assert!(!egress_for_parent.create().is_err());
    assert!(!custom.attach().is_err());
    assert!(!destroyer.destroy().is_err());
    assert!(custom.attach().is_err());
}

#[test]
#[serial]
fn test_tc_detach_basic() {
    bump_rlimit_mlock();
    let (_obj, tc_builder, mut destroyer) = test_helper_get_tc_builder("handle_tc");
    assert!(!destroyer.destroy().is_err());

    let mut egress = tc_builder.hook(EGRESS);
    let mut ingress = tc_builder.hook(INGRESS);
    let mut custom = tc_builder.hook(CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    custom.handle(2);

    assert!(!egress.create().is_err());
    assert!(!egress.attach().is_err());
    assert!(!ingress.attach().is_err());
    assert!(!custom.attach().is_err());

    assert!(!egress.detach().is_err());
    assert!(!ingress.detach().is_err());
    assert!(!custom.detach().is_err());

    assert!(!egress.detach().is_err());
    assert!(!ingress.detach().is_err());
    assert!(!custom.detach().is_err());
}

#[test]
#[serial]
fn test_tc_query() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, mut destroyer) = test_helper_get_tc_builder("handle_tc");
    assert!(!destroyer.destroy().is_err());

    let mut egress = tc_builder.hook(EGRESS);
    assert!(!egress.create().is_err());
    assert!(!egress.attach().is_err());
    assert!(!egress.query().is_err());
    
    assert!(!egress.detach().is_err());
    assert!(egress.query().is_err());
    
    assert!(!egress.attach().is_err());
    assert!(!egress.query().is_err());
    
    assert!(!egress.destroy().is_err());
    assert!(egress.query().is_err());
    
    assert!(!egress.attach().is_err());
    assert!(!egress.query().is_err());
    
    assert!(!destroyer.destroy().is_err());
    assert!(egress.query().is_err());

    let mut ingress = tc_builder.hook(EGRESS);
    assert!(!ingress.create().is_err());
    assert!(!ingress.attach().is_err());
    assert!(!ingress.query().is_err());
    
    assert!(!ingress.detach().is_err());
    assert!(ingress.query().is_err());
    
    assert!(!ingress.attach().is_err());
    assert!(!ingress.query().is_err());
    
    assert!(!ingress.destroy().is_err());
    assert!(ingress.query().is_err());
    
    assert!(!ingress.attach().is_err());
    assert!(!ingress.query().is_err());
    
    assert!(!destroyer.destroy().is_err());
    assert!(ingress.query().is_err());

    let mut custom = tc_builder.hook(CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    assert!(!ingress.create().is_err());
    assert!(!custom.attach().is_err());
    assert!(!custom.query().is_err());
   
    assert!(!custom.detach().is_err());
    assert!(custom.query().is_err());
    
    assert!(!custom.attach().is_err());
    assert!(!custom.query().is_err());
    
    assert!(!destroyer.destroy().is_err());
    assert!(custom.query().is_err());
} 
