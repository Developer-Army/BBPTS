@echo off
echo ⏱️  Running benchmarks...
go test -bench=. -benchmem -run=^^$ ./... > benchmark.txt
echo ✅ Benchmark results saved to benchmark.txt
pause
