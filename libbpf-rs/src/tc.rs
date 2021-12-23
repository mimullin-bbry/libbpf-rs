use nix::errno;
use nix::errno::Errno::{EEXIST, EINVAL};

use crate::*;

pub type TcAttachPoint = libbpf_sys::bpf_tc_attach_point;
pub const INGRESS: TcAttachPoint = libbpf_sys::BPF_TC_INGRESS;
pub const EGRESS: TcAttachPoint = libbpf_sys::BPF_TC_EGRESS;
pub const CUSTOM: TcAttachPoint = libbpf_sys::BPF_TC_CUSTOM;

pub type TcFlags = libbpf_sys::bpf_tc_flags;
pub const BPF_TC_F_REPLACE: TcFlags = libbpf_sys::BPF_TC_F_REPLACE;

pub const TC_H_INGRESS: u32 = 0xFFFFFFF1;
pub const TC_H_CLSACT: u32 = TC_H_INGRESS;

pub const TC_H_MIN_INGRESS: u32 = 0xFFF2;
pub const TC_H_MIN_EGRESS: u32 = 0xFFF3;
/// The BPF TC subsystem has different control paths from other BPF programs
/// As such a BPF program using a TC Hook (SEC("classifier") | SEC("tc")) must be operated
/// more independently from other [libbpf-rs::Program]s where the program itself can
/// be attach_*() a program using TC must grab a hook point, or create one
/// and attach from the TcHook
///
/// Documentation about the libbpf TC interface can be found here
/// https://lwn.net/ml/bpf/20210512103451.989420-3-memxor@gmail.com/
///
/// An example of using a BPF TC program can be seen in [examples/tc_whitelist_ports/src/main.rs]
///
/// Represents a Hook Point for a Traffic Control (TC) bpf program
///
/// This object exposes operations to create and attach a bpf_tc_hook
/// into the TC subsystem
#[derive(Clone, Copy, Debug)]
pub struct TcHook {
    hook: libbpf_sys::bpf_tc_hook,
    opts: libbpf_sys::bpf_tc_opts,
}

impl TcHook {
    /// Create a New TcHook given the file descriptor of the loaded SEC("classifier") Program
    /// See: [libbpf-rs::Program]
    pub fn new(fd: i32) -> Self {
        let mut tc_hook = TcHook {
            hook: libbpf_sys::bpf_tc_hook::default(),
            opts: libbpf_sys::bpf_tc_opts::default(),
        };

        tc_hook.hook.sz = std::mem::size_of::<libbpf_sys::bpf_tc_hook>() as u64;
        tc_hook.opts.sz = std::mem::size_of::<libbpf_sys::bpf_tc_opts>() as u64;
        tc_hook.opts.prog_fd = fd;

        tc_hook
    }

    /// create a TcHook creates a New bpf_tc_hook
    ///
    /// if a TcHook already exists with the same parameters as the hook calling
    /// create(), this function will still succeed.
    ///
    /// Will always fail on a BPF_TC_CUSTOM hook
    pub fn create(&mut self) -> Result<Self> {
        let err = unsafe { libbpf_sys::bpf_tc_hook_create(&mut self.hook as *mut _) };
        // the hook may already exist, this is not an error
        if err != 0 && err != -(EEXIST as i32) {
            Err(Error::System(err))
        } else {
            Ok(*self)
        }
    }

    /// Set the interface to be used
    ///
    /// Interfaces can be listed by using ip link command from the iproute2 software package
    pub fn ifindex(&mut self, idx: i32) -> &mut Self {
        self.hook.ifindex = idx;
        self
    }

    /// Set what type of TC point to attach onto
    ///
    /// EGRESS, INGRESS, or CUSTOM
    ///
    /// An EGRESS|INGRESS hook can be used as an attach_point for calling
    /// the destroy() method to remove the clsact bpf tc qdisc, but cannot
    /// be used to attach()
    pub fn attach_point(&mut self, ap: TcAttachPoint) -> &mut Self {
        self.hook.attach_point = ap;
        self
    }

    /// Set the parent of a hook
    /// Will return EINVAL if set upon an EGRESS/INGRESS/EGRESS|INGRESS hook
    ///
    /// Must be set on a CUSTOM hook
    /// Current acceptable values are TC_H_CLSACT for maj, and
    /// TC_H_MIN_EGRESS or TC_H_MIN_INGRESS for min
    pub fn parent(&mut self, maj: u32, min: u32) -> &mut Self {
        /* values from libbpf.h BPF_TC_PARENT() */
        let parent = (maj & 0xFFFF0000_u32) | (min & 0x0000FFFF_u32);
        self.hook.parent = parent;
        self
    }

    /// Set whether this hook should replace an existing hook
    ///
    /// If replace is not true upon attach, and a hook already exists
    /// an EEXIST error will be returned from attach()
    pub fn replace(&mut self, replace: bool) -> &mut Self {
        if replace {
            self.opts.flags = BPF_TC_F_REPLACE;
        } else {
            self.opts.flags = 0;
        }
        self
    }

    /// Set the handle of a hook.
    /// If unset upon attach, the kernel will assign a handle for the hook
    pub fn handle(&mut self, handle: u32) -> &mut Self {
        self.opts.handle = handle;
        self
    }

    /// Set the priority of a hook
    /// if unset upon attach, the kernel will assign a priority for the hook
    pub fn priority(&mut self, priority: u32) -> &mut Self {
        self.opts.priority = priority;
        self
    }

    /// Query a hook to inspect the program identifier (prog_id)
    pub fn query(&mut self) -> Result<u32> {
        let mut opts = self.opts;
        opts.prog_id = 0;
        opts.prog_fd = 0;
        opts.flags = 0;

        let err = unsafe { libbpf_sys::bpf_tc_query(&self.hook as *const _, &mut opts as *mut _) };
        if err != 0 {
            Err(Error::System(errno::errno()))
        } else {
            Ok(opts.prog_id)
        }
    }

    /// Attach the TcHook so that the program starts processing
    ///
    /// Once the hook is processing, changing the values will have no effect
    /// unless the hook is attach()'d again (replace(true) being required)
    ///
    /// Users can create a second hook by changing the handle, the priority
    /// or the attach_point and calling the attach() method again.
    /// Beware doing this.  It might be better to Copy the TcHook and change
    /// the values on the copied hook for easier detach()
    ///
    /// NOTE: Once a TcHook is attached, it, and the maps it uses,
    ///       will outlive the userspace application that spawned them
    ///       Make sure to detach if this is not desired
    pub fn attach(&mut self) -> Result<Self> {
        self.opts.prog_id = 0;
        let err =
            unsafe { libbpf_sys::bpf_tc_attach(&self.hook as *const _, &mut self.opts as *mut _) };
        if err != 0 {
            Err(Error::System(errno::errno()))
        } else {
            Ok(*self)
        }
    }

    /// Detach a TcHook
    pub fn detach(&mut self) -> Result<()> {
        let mut opts = self.opts;
        opts.prog_id = 0;
        opts.prog_fd = 0;
        opts.flags = 0;

        let err = unsafe { libbpf_sys::bpf_tc_detach(&self.hook as *const _, &opts as *const _) };
        if err != 0 && err != -(errno::Errno::ENOENT as i32) {
            Err(Error::System(err as i32))
        } else {
            self.opts.prog_id = 0;
            Ok(())
        }
    }

    /// Destroy attached filters
    ///
    /// If called on a hook with an attach_point of EGRESS, will detach all EGRESS hooks
    /// If called on a hook with an attach_point of INGRESS, will detach all INGRESS hooks
    ///
    /// If called on a hook with an attach_point of EGRESS|INGRESS, will destroy the clsact tc
    /// qdisc and detach all hooks
    ///
    /// Will error with EOPNOTSUPP if attach_point is BPF_TC_CUSTOM
    ///
    /// It is good practice to query before destroying as the tc qdisc may be used
    /// by multiple programs
    pub fn destroy(&mut self) -> Result<()> {
        let err = unsafe { libbpf_sys::bpf_tc_hook_destroy(&mut self.hook as *mut _) };
        if err == -(EINVAL as i32) && self.hook.attach_point == EGRESS | INGRESS {
            // do not error if trying to destroy clsact tc qdisc and it doesn't exist
            Ok(())
        } else if err != 0 {
            println!("det {}", err);
            Err(Error::System(err as i32))
        } else {
            Ok(())
        }
    }
}

/// A TcHookBuilder is a way to ergonomically create multiple TcHooks
/// All with similar initial values
///
/// Once a TcHook is created via the hook() method, the TcHook's values can still
/// be adjusted before attach() is called
#[derive(Debug, Default)]
pub struct TcHookBuilder {
    fd: i32,
    ifindex: i32,
    parent_maj: u32,
    parent_min: u32,
    replace: bool,
    handle: u32,
    priority: u32,
}

impl TcHookBuilder {
    pub fn new() -> Self {
        TcHookBuilder::default()
    }

    /// Set the initial file descriptor for created hooks
    /// this fd should come from a loaded libbpf_rs::Program
    pub fn fd(&mut self, fd: i32) -> &mut Self {
        self.fd = fd;
        self
    }

    /// Set the initial interface index to attach the hook on
    pub fn ifindex(&mut self, ifindex: i32) -> &mut Self {
        self.ifindex = ifindex;
        self
    }

    /// Set the initial parent of a hook
    pub fn parent(&mut self, maj: u32, min: u32) -> &mut Self {
        self.parent_maj = maj;
        self.parent_min = min;
        self
    }

    /// Set whether created hooks should replace existing hooks
    pub fn replace(&mut self, replace: bool) -> &mut Self {
        self.replace = replace;
        self
    }

    /// Set the initial handle for a hook
    pub fn handle(&mut self, handle: u32) -> &mut Self {
        self.handle = handle;
        self
    }

    /// Set the initial priority for a hook
    pub fn priority(&mut self, priority: u32) -> &mut Self {
        self.priority = priority;
        self
    }

    /// Create a Hook given the values previously set
    ///
    /// Once a hook is created, the values can still be changed on the TcHook
    /// by calling the TcHooks setter methods
    pub fn hook(&self, attach_point: TcAttachPoint) -> TcHook {
        let mut hook = TcHook::new(self.fd);
        hook.ifindex(self.ifindex)
            .handle(self.handle)
            .priority(self.priority)
            .parent(self.parent_maj, self.parent_min)
            .replace(self.replace)
            .attach_point(attach_point);

        hook
    }
}
