// TPCH Benchmark Suite
// Paper: TPCH benchmark queries for performance evaluation
// Small, medium, large scale tests

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;

use halo2_proofs::{circuit::Value, pasta::EqAffine, poly::commitment::Params};
use pasta_curves::pallas::Base as Fr;
use poneglyphdb::{
    circuit::PoneglyphCircuit,
    database::DatabaseCommitment,
    prover::{MockProverHelper, Prover, Verifier},
    sql::{SQLCompiler, SQLParser},
};

/// TPCH Benchmark Suite
/// Generates data for small, medium, large scale tests
pub struct TPCHBenchmark {
    /// Small scale: 100 rows
    pub small_scale: HashMap<String, HashMap<String, Vec<u64>>>,
    /// Medium scale: 10,000 rows
    pub medium_scale: HashMap<String, HashMap<String, Vec<u64>>>,
    /// Large scale: 1,000,000 rows
    pub large_scale: HashMap<String, HashMap<String, Vec<u64>>>,
}

impl TPCHBenchmark {
    /// Create new TPCH benchmark suite
    pub fn new() -> Self {
        Self {
            small_scale: Self::generate_data(100),
            medium_scale: Self::generate_data(10_000),
            large_scale: Self::generate_data(1_000_000),
        }
    }

    /// Generate test data
    fn generate_data(num_rows: usize) -> HashMap<String, HashMap<String, Vec<u64>>> {
        let mut table = HashMap::new();

        // Customer table
        let mut customer = HashMap::new();
        let mut customer_id = Vec::new();
        let mut customer_name = Vec::new();
        let mut customer_age = Vec::new();

        for i in 0..num_rows {
            customer_id.push(i as u64);
            customer_name.push((i * 1000) as u64); // Simplified name representation
            customer_age.push((20 + (i % 60)) as u64); // Age between 20-80
        }

        customer.insert("id".to_string(), customer_id);
        customer.insert("name".to_string(), customer_name);
        customer.insert("age".to_string(), customer_age);
        table.insert("customer".to_string(), customer);

        // Order table
        let mut order = HashMap::new();
        let mut order_id = Vec::new();
        let mut customer_id = Vec::new();
        let mut order_amount = Vec::new();

        for i in 0..num_rows {
            order_id.push(i as u64);
            customer_id.push((i % num_rows) as u64); // Foreign key to customer
            order_amount.push((100 + (i % 10000)) as u64); // Amount between 100-10099
        }

        order.insert("id".to_string(), order_id);
        order.insert("customer_id".to_string(), customer_id);
        order.insert("amount".to_string(), order_amount);
        table.insert("order".to_string(), order);

        table
    }

    /// TPCH Query 1: Simple SELECT with WHERE
    pub fn query1(&self, scale: &str) -> String {
        match scale {
            "small" => "SELECT id, name FROM customer WHERE age < 50".to_string(),
            "medium" => "SELECT id, name FROM customer WHERE age < 50".to_string(),
            "large" => "SELECT id, name FROM customer WHERE age < 50".to_string(),
            _ => panic!("Invalid scale"),
        }
    }

    /// TPCH Query 2: SELECT with ORDER BY
    pub fn query2(&self, scale: &str) -> String {
        match scale {
            "small" => "SELECT id, amount FROM order ORDER BY amount ASC".to_string(),
            "medium" => "SELECT id, amount FROM order ORDER BY amount ASC".to_string(),
            "large" => "SELECT id, amount FROM order ORDER BY amount ASC".to_string(),
            _ => panic!("Invalid scale"),
        }
    }

    /// TPCH Query 3: SELECT with GROUP BY and aggregation
    pub fn query3(&self, scale: &str) -> String {
        match scale {
            "small" => {
                "SELECT customer_id, sum(amount) FROM order GROUP BY customer_id".to_string()
            }
            "medium" => {
                "SELECT customer_id, sum(amount) FROM order GROUP BY customer_id".to_string()
            }
            "large" => {
                "SELECT customer_id, sum(amount) FROM order GROUP BY customer_id".to_string()
            }
            _ => panic!("Invalid scale"),
        }
    }

    /// TPCH Query 4: SELECT with JOIN
    pub fn query4(&self, scale: &str) -> String {
        match scale {
            "small" => "SELECT c.id, o.amount FROM customer c JOIN order o ON c.id = o.customer_id"
                .to_string(),
            "medium" => {
                "SELECT c.id, o.amount FROM customer c JOIN order o ON c.id = o.customer_id"
                    .to_string()
            }
            "large" => "SELECT c.id, o.amount FROM customer c JOIN order o ON c.id = o.customer_id"
                .to_string(),
            _ => panic!("Invalid scale"),
        }
    }
}

/// Benchmark: SQL Parsing
fn benchmark_sql_parsing(c: &mut Criterion) {
    let benchmark = TPCHBenchmark::new();

    let mut group = c.benchmark_group("sql_parsing");

    for scale in ["small", "medium", "large"] {
        for query_num in 1..=4 {
            let query = match query_num {
                1 => benchmark.query1(scale),
                2 => benchmark.query2(scale),
                3 => benchmark.query3(scale),
                4 => benchmark.query4(scale),
                _ => continue,
            };

            group.bench_with_input(
                BenchmarkId::new(format!("query{}", query_num), scale),
                &query,
                |b, sql| {
                    b.iter(|| {
                        black_box(SQLParser::parse(sql).unwrap());
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark: SQL Compilation
fn benchmark_sql_compilation(c: &mut Criterion) {
    let benchmark = TPCHBenchmark::new();

    let mut group = c.benchmark_group("sql_compilation");

    for scale in ["small", "medium", "large"] {
        let table_data = match scale {
            "small" => &benchmark.small_scale,
            "medium" => &benchmark.medium_scale,
            "large" => &benchmark.large_scale,
            _ => continue,
        };

        for query_num in 1..=4 {
            let query_str = match query_num {
                1 => benchmark.query1(scale),
                2 => benchmark.query2(scale),
                3 => benchmark.query3(scale),
                4 => benchmark.query4(scale),
                _ => continue,
            };

            let query = SQLParser::parse(&query_str).unwrap();

            group.bench_with_input(
                BenchmarkId::new(format!("query{}", query_num), scale),
                &query,
                |b, q| {
                    b.iter(|| {
                        black_box(SQLCompiler::compile(q, table_data).unwrap());
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark: Circuit Synthesis (Mock Prover)
fn benchmark_circuit_synthesis(c: &mut Criterion) {
    let benchmark = TPCHBenchmark::new();

    let mut group = c.benchmark_group("circuit_synthesis");

    for scale in ["small", "medium"] {
        // Large scale can be very slow, only test small and medium
        let table_data = match scale {
            "small" => &benchmark.small_scale,
            "medium" => &benchmark.medium_scale,
            _ => continue,
        };

        for query_num in 1..=4 {
            let query_str = match query_num {
                1 => benchmark.query1(scale),
                2 => benchmark.query2(scale),
                3 => benchmark.query3(scale),
                4 => benchmark.query4(scale),
                _ => continue,
            };

            let query = SQLParser::parse(&query_str).unwrap();
            let compiled = SQLCompiler::compile(&query, table_data).unwrap();

            // Create database commitment
            let db_data: Vec<(u64, u64)> = table_data
                .values()
                .flat_map(|t| {
                    t.values()
                        .flatten()
                        .enumerate()
                        .map(|(i, &v)| (i as u64, v))
                        .collect::<Vec<_>>()
                })
                .collect();
            let db_commitment = DatabaseCommitment::new(&db_data);

            let circuit = PoneglyphCircuit {
                db_commitment: Value::known(db_commitment.commitment),
                query_result: Value::unknown(),
                range_checks: compiled.range_checks,
                sorts: compiled.sorts,
                group_bys: compiled.group_bys,
                joins: compiled.joins,
                aggregations: compiled.aggregations,
            };

            // Circuit size (k): 2^k rows can be used
            // Sort operations use many rows, so we calculate k dynamically
            // For each sort operation: approximately 12n - 9 rows (n = sorted_values.len())
            // For range checks: 2 rows per range check (check_less_than)
            //
            // Simple solution: choose k large enough (k=12 = 4096 rows should be sufficient)
            let k = 12; // Circuit size (2^12 = 4096 rows)

            group.bench_with_input(
                BenchmarkId::new(format!("query{}", query_num), scale),
                &circuit,
                |b, circ| {
                    b.iter(|| {
                        // Circuit has only 1 instance column
                        // Row 0: db_commitment, Row 1: query_result
                        let public_inputs = vec![vec![
                            db_commitment.commitment, // Row 0
                            Fr::zero(),               // Row 1: Placeholder query result
                        ]];
                        black_box(
                            MockProverHelper::mock_prove_and_verify(circ, &public_inputs, k)
                                .unwrap(),
                        );
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark: Proof Generation (Real Prover)
fn benchmark_proof_generation(c: &mut Criterion) {
    let benchmark = TPCHBenchmark::new();

    // Only test small scale (proof generation is very slow)
    let table_data = &benchmark.small_scale;
    let query_str = benchmark.query1("small");
    let query = SQLParser::parse(&query_str).unwrap();
    let compiled = SQLCompiler::compile(&query, table_data).unwrap();

    // Create database commitment
    let db_data: Vec<(u64, u64)> = table_data
        .values()
        .flat_map(|t| {
            t.values()
                .flatten()
                .enumerate()
                .map(|(i, &v)| (i as u64, v))
                .collect::<Vec<_>>()
        })
        .collect();
    let db_commitment = DatabaseCommitment::new(&db_data);

    let circuit = PoneglyphCircuit {
        db_commitment: Value::known(db_commitment.commitment),
        query_result: Value::unknown(),
        range_checks: compiled.range_checks,
        sorts: compiled.sorts,
        group_bys: compiled.group_bys,
        joins: compiled.joins,
        aggregations: compiled.aggregations,
    };

    let k = 10;
    let params = Params::<EqAffine>::new(k);

    let prover = Prover::new(&params, &circuit).unwrap();
    let verifier = Verifier::new(&params, &circuit).unwrap();

    let public_inputs = vec![
        vec![db_commitment.commitment],
        vec![Fr::zero()], // Placeholder query result
    ];

    c.bench_function("proof_generation", |b| {
        b.iter(|| {
            let proof = black_box(prover.prove(&params, &circuit, &public_inputs).unwrap());
            black_box(verifier.verify(&params, &proof, &public_inputs).unwrap());
        });
    });
}

// Memory usage monitoring helper
// Production requires more advanced memory profiling tooling
// Currently unused, can be added in the future
// fn measure_memory_usage<T>(f: impl FnOnce() -> T) -> (u64, T) {
//     // Simple memory measurement (production requires more advanced tooling)
//     let start = Instant::now();
//     let result = f();
//     let duration = start.elapsed();
//
//     // Placeholder for memory usage (production requires proper memory profiling)
//     let memory_estimate = duration.as_millis() as u64 * 1024; // Rough estimate
//
//     (memory_estimate, result)
// }

criterion_group!(
    benches,
    benchmark_sql_parsing,
    benchmark_sql_compilation,
    benchmark_circuit_synthesis,
    benchmark_proof_generation
);
criterion_main!(benches);
