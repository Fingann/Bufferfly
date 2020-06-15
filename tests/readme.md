In order to recreate binaries used for testing, use "vuln_create.py". Provide the program with the following arguments and keep the resulting files in the same folder as the testing suite. (Note: this has only been tested on Solus, I'm not completely sure the results will be the same on other OSes)
$ python3 vuln_create.py --name test500 --bufferSize 500
$ python3 vuln_create.py --name test --goalFunction supersecret
$ python3 vuln_create.py --name test-no-bof --overflowSize 0
