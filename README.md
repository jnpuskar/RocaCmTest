# RocaCmTest
Windows tool that analyzes your computer for Infineon TPM weak RSA keys (CVE-2017-15361) 

The tool was created and inspired by this GitHub project (https://github.com/crocs-muni/roca). The detection logic used is the same as  there. This tool just represents a more user-friendly and comprehensive version of detecting the vulnerability.

This application is a stand-alone windows executable that upon execution will test your TPM chip and certificates in user and system store.  

Details of test:
There are 2 phases of test carried on. First the application attempts to generate RSA 2048 key using your TPM. This is done via employing either MS Platform Crypto Provider (TPM wrapper) on Win 8 and newer OR via Charismathics TPM Software Stack on Windows 7. As soon as the RSA 2048 key is generated its public part is checked against CVE-2017-15361. The key is then deleted.
In second phase depending on parameters the tool inspect certificate, directory of certificates or user & system certificate stores. 

The most common scenarion is executing the test by double-clicking the RocaCmTest.exe. This results in testing the user & system certificate stores. Since we optimize user experience for this scenario the console window will remain opened till <ENTER> is pressed.

After the tool is done a result is displayed with issues in red and warnings in yellow.

The vulnerability is described here: https://crocs.fi.muni.cz/public/papers/rsa_ccs17

Infineon info is here: https://www.infineon.com/cms/en/product/promopages/tpm-update/?redirId=59160
