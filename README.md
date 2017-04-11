# bitcoin-blk-file-reader
Reads the blkXXXXX.dat files from bitcoind (Bitcoin-Core)
The implementation is in python. 

## Usage
Normally your bitcoind client stores the blk files in $HOME/.bitcoin/blocks/

To read the first blk-file, which is blk00000.dat:

```shell
python analyze.py .bitcoin/blocks/blk00000.dat
```

After that you get the output to the console. This script is very easy to understand and you can use it on your own.
