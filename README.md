# bitcoin-blk-file-reader
Reads the blkXXXXX.dat files from bitcoind (Bitcoin-Core)
The implementation is in python and includes the witness format for the extended transaction format and includes correct transaction hash calculation, which was initially forgotten to add here.

## Usage
Normally your bitcoind client stores the blk files in $HOME/.bitcoin/blocks/

To read the first blk-file, which is blk00000.dat:

```shell
python analyze.py $HOME/.bitcoin/blocks/blk00000.dat
```

After that you get the output to the console. This script is very easy to understand and you can use it on your own.

NOTICE: Some addresses are not calculated yet, they are multisig addresses, I did not have time to add the code, but I will. Further the code is not very nice, since this was my first try doing this long ago. But feel free to contact me if you have any questions.
