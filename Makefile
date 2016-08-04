netwatcher: netwatcher.cpp
	$(CXX) $<  -o $@ -framework CoreFoundation -framework SystemConfiguration

clean:
	$(RM) netwatcher