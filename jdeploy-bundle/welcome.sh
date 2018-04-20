#!/usr/bin/env bash

CURRENTDIR=`dirname $0`
binLink=~/bin/javassltest
if [ -L ${binLink} ] ; then
   rm ${binLink}
elif [ -e ${binLink} ] ; then
   echo "Looks like it is the first run. Have fun!"
fi
ln -s $CURRENTDIR/javassltest.sh $binLink
echo "A softlink $binLink has been added!"

if [[ :$PATH: == *:$HOME/bin:* ]]; then
    echo "Please add below to your PATH";
    echo "PATH=\$HOME/bin:\$PATH"
fi

source $binLink