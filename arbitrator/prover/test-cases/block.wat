(func
	(i32.const 1)
	(block
		(block
			(br 1)
			(unreachable)
		)
		(unreachable)
	)
	(block (param i32)
		(br_if 0)
		(unreachable)
	)
	(block
		(block
			(i32.const 2)
			(br_table 0 0 1 0 0)
			(unreachable)
		)
		(unreachable)
	)
	(block
		(block
			(i32.const 8)
			(br_table 0 0 0 0 1)
			(unreachable)
		)
		(unreachable)
	)

	(i32.const 1)
	(block
		(i64.const -64)
		(i64.const -64)
		(br 0)
		(unreachable)
	)
	(block
		(i64.const -64)
		(i32.const 1)
		(br_if 0)
		(unreachable)
	)
	(block (param i32)
		(br_if 0)
		(unreachable)
	)
	(block (result i32)
		(i64.const 0)
		(i32.const 1)
		(i32.const 1)
		(br_if 0)
		(unreachable)
	)
	(block (param i32)
		(br_if 0)
		(unreachable)
	)
	(i32.const 1)
	(block
		(i32.const 1)
		(i64.const -64)
		(br 0)
		(unreachable)
	)
	(br_if 0)
)

(start 0)
(memory (export "memory") 0 0)
