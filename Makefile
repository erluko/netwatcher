netwatcher: netwatcher.cpp
	$(CXX) $<  -o $@ -framework CoreFoundation -framework SystemConfiguration

netwatcher-test: netwatcher
	cp $< $@

test: netwatcher-test
	./run_tests.sh

clean:
	$(RM) netwatcher netwatcher-test