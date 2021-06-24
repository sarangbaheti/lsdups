linux binary is included in repo, for windows- build it with solution file.
\
There is lot more to be done:
 - partial and full checksums for files
 - memory mapping of files (for direct comparison)
 - something better for comparing images (opencv perhaps)
 - multi-threading/asynchrony where possible


-----------------------------------------------------------

```
 sarang>~\\code\dups>./lsdups.out -d /

Author: Sarang Baheti, c 2021
Source: https://github.com/sarangbaheti/lsdups
usage:
   lsdups -d <dir> -p *asdf*.txt

Found 1568860 matching files
(FilesTraversed: 1568860, DirsTraversed: 171173 in 24495 milli-seconds)

Found 191129 potential duplicates (842 ms)
```

-----------------------------------------------------------
to compile on linux (g++9):

```
g++ -std=c++17 -O2 ./dups/Source.cpp -ltbb -o ./lsdups.out
```

to compile on windows:
 - just use sln/vcxproj file


