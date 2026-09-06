use std::collections::HashMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use u7s_scheduler::{
    resource_fits, select_node_with_capacity, NodeAllocatable, NodeItem, NodeList, NodeMetadata,
    NodeSpec, NodeStatus, NodeUsage, PendingPod, ResourceRequests,
};

/// 100m cpu / 128Mi memory: a realistic single-container request, small next
/// to every node's generous allocatable below so capacity is never the
/// reason a node is rejected — only the nodeSelector mismatch is.
fn realistic_pending_pod() -> PendingPod {
    PendingPod {
        namespace: "default".to_owned(),
        pod_name: "bench-pod".to_owned(),
        node_selector: [("bench".to_owned(), "target".to_owned())].into(),
        priority: 0,
        tolerations: Vec::new(),
        node_affinity: None,
        labels: HashMap::new(),
        pod_affinity_terms: Vec::new(),
        pod_anti_affinity_terms: Vec::new(),
        requests: ResourceRequests {
            cpu_milli: 100,
            memory_milli: 128 * 1024 * 1024 * 1000,
            ephemeral_storage_milli: 0,
            extended: Default::default(),
        },
        host_ports: Vec::new(),
        pvc_names: Vec::new(),
        pv_node_affinities: Vec::new(),
        topology_spread_constraints: Vec::new(),
        csi_volume_counts: Default::default(),
        read_write_once_pod_pvcs: Vec::new(),
        unbound_csi_pvc_drivers: Vec::new(),
    }
}

fn roomy_node(name: String, selector_value: &str) -> NodeItem {
    NodeItem {
        metadata: NodeMetadata {
            name,
            labels: [("bench".to_owned(), selector_value.to_owned())].into(),
        },
        spec: NodeSpec::default(),
        status: NodeStatus {
            allocatable: NodeAllocatable {
                pods: "110".to_owned(),
                cpu: "32".to_owned(),
                memory: "128Gi".to_owned(),
                ephemeral_storage: "500Gi".to_owned(),
                extended: Default::default(),
            },
            capacity: NodeAllocatable::default(),
        },
        csi_driver_headroom: Default::default(),
        csi_registered_drivers: Default::default(),
    }
}

/// `size` nodes where only the LAST one's label matches the pod's
/// nodeSelector — the worst case for `select_node_with_capacity`'s
/// `.find()`: every earlier node is visited and rejected by
/// `node_qualifies_for_pod` before the match is reached, so wall-clock
/// actually scales with list size instead of returning after one check.
fn node_list_matching_last(size: usize) -> NodeList {
    let mut items: Vec<NodeItem> = (0..size - 1)
        .map(|i| roomy_node(format!("worker-{i}"), "not-it"))
        .collect();
    items.push(roomy_node(format!("worker-{}", size - 1), "target"));
    NodeList { items }
}

fn bench_select_node_with_capacity(c: &mut Criterion) {
    let pod = realistic_pending_pod();
    let usage: HashMap<String, NodeUsage> = HashMap::new();
    let mut group = c.benchmark_group("select_node_with_capacity");
    for size in [10usize, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || node_list_matching_last(size),
                |list| {
                    select_node_with_capacity(
                        black_box(list),
                        black_box(&pod),
                        black_box(&usage),
                        black_box(&[]),
                    )
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// `resource_fits`'s only collection-shaped input is `extended` (cpu/memory/
/// ephemeral-storage are fixed scalar fields), so it is sized 10/100/1000
/// entries instead of a node-list count — every entry is requested AND fits,
/// the worst case for `.all(...)`: a single mismatch would short-circuit
/// early, but a full match must evaluate every entry.
fn bench_resource_fits(c: &mut Criterion) {
    let mut group = c.benchmark_group("resource_fits");
    for size in [10usize, 100, 1000] {
        let allocatable = NodeAllocatable {
            pods: String::new(),
            cpu: "32".to_owned(),
            memory: "128Gi".to_owned(),
            ephemeral_storage: "500Gi".to_owned(),
            extended: (0..size)
                .map(|i| (format!("vendor.example/res-{i}"), "1000".to_owned()))
                .collect(),
        };
        let used = ResourceRequests::default();
        let requested = ResourceRequests {
            cpu_milli: 100,
            memory_milli: 128 * 1024 * 1024 * 1000,
            ephemeral_storage_milli: 0,
            extended: (0..size)
                .map(|i| (format!("vendor.example/res-{i}"), 500i64))
                .collect(),
        };
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                resource_fits(
                    black_box(&allocatable),
                    black_box(&used),
                    black_box(&requested),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_select_node_with_capacity,
    bench_resource_fits
);
criterion_main!(benches);
