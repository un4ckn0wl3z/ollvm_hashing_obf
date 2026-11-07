CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -I.

# Default target
all: test_vm protected

# VM correctness test (run this first to verify everything works)
test_vm: test_vm.cpp protection/protection.h protection/vm_defs.h \
         protection/vm_engine.h protection/vm_compiler.h protection/vm_hash.h \
         protection/string_crypt.h protection/anti_analysis.h protection/control_flow.h
	$(CXX) $(CXXFLAGS) -o $@ test_vm.cpp

# Protected binary
protected: protected_source.cpp protection/protection.h protection/vm_defs.h \
           protection/vm_engine.h protection/vm_compiler.h protection/vm_hash.h \
           protection/string_crypt.h protection/anti_analysis.h protection/control_flow.h
	$(CXX) $(CXXFLAGS) -o $@ protected_source.cpp

# Run tests
test: test_vm
	./test_vm

# Inspect: show what strings are visible in the binary (should find NO passwords)
inspect: protected
	@echo "=== Strings visible in protected binary ==="
	@echo "(You should NOT see 'Enter the password', 'Good Job', 'Denied', or '6uncr4ck6')"
	@echo ""
	@strings protected | grep -iE "(password|enter|good|denied|uncr4ck)" || \
		echo "  >> None found — strings are encrypted!"
	@echo ""
	@echo "=== For comparison, strings in the unprotected test binary ==="
	@strings test_vm | grep -iE "(password|enter|good|denied|hello)" || true

clean:
	rm -f test_vm protected

.PHONY: all test inspect clean
